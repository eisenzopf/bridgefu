from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[4]
RECIPE_ROOT = ROOT / "recipes/vapi-amazon-connect-screen-pop"
COMMON = RECIPE_ROOT / "lambda/common"
sys.path.insert(0, str(COMMON))
from vapi_provisioning import ProvisioningConfig  # noqa: E402


SCRIPT = ROOT / "scripts" / "aws-recipe-live-test.py"
SPEC = importlib.util.spec_from_file_location("aws_recipe_live_test_vapi", SCRIPT)
assert SPEC and SPEC.loader
LIVE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = LIVE
SPEC.loader.exec_module(LIVE)


class VapiLiveControllerTests(unittest.TestCase):
    def ledger(self) -> dict[str, object]:
        root_stack_id = (
            "arn:aws:cloudformation:us-west-2:123456789012:stack/"
            "bridgefu-bft-20990101a/00000000-0000-0000-0000-000000000001"
        )
        return {
            "execution_id": "bft-20990101a",
            "account_id": "123456789012",
            "partition": "aws",
            "region": "us-west-2",
            "stack_name": "bridgefu-bft-20990101a",
            "review_stack_id": root_stack_id,
            "stack_id": root_stack_id,
            "application_stack_name": (
                "arn:aws:cloudformation:us-west-2:123456789012:stack/"
                "application/00000000-0000-0000-0000-000000000002"
            ),
            "vapi_api_key_secret_arn": (
                "arn:aws:secretsmanager:us-west-2:123456789012:"
                "secret:bridgefu-bft-20990101a-vapi-key"
            ),
            "events": [],
        }

    def test_binding_persists_all_external_ids_and_rejects_drift(self):
        ledger = self.ledger()
        root_stack_id = ledger["stack_id"]
        application_stack_id = ledger["application_stack_name"]
        stack_id = (
            "arn:aws:cloudformation:us-west-2:123456789012:stack/"
            "vapi/00000000-0000-0000-0000-000000000003"
        )
        description = {
            "StackId": stack_id,
            "ParentId": application_stack_id,
            "RootId": root_stack_id,
            "Outputs": [
                {"OutputKey": "AssistantId", "OutputValue": "assistant_1"},
                {"OutputKey": "PrepareToolId", "OutputValue": "tool_1"},
                {
                    "OutputKey": "WebhookCredentialId",
                    "OutputValue": "credential_1",
                },
            ],
        }
        handoff_id = (
            "arn:aws:cloudformation:us-west-2:123456789012:stack/"
            "handoff/00000000-0000-0000-0000-000000000004"
        )
        handoff = {
            "StackId": handoff_id,
            "ParentId": application_stack_id,
            "RootId": root_stack_id,
            "Outputs": [
                {
                    "OutputKey": "PrepareUrl",
                    "OutputValue": "https://handoff.example.test/prepare",
                }
            ],
        }

        def nested(_ledger, _environment, logical_id, _parent):
            return {
                "RecipeApplication": application_stack_id,
                "VapiResources": stack_id,
                "HandoffService": handoff_id,
            }[logical_id]

        def stack(_ledger, _environment, requested_stack_id):
            application = {
                "StackId": application_stack_id,
                "ParentId": root_stack_id,
                "RootId": root_stack_id,
            }
            return {
                application_stack_id: application,
                stack_id: description,
                handoff_id: handoff,
            }[requested_stack_id]

        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            LIVE, "nested_stack_id", side_effect=nested
        ), mock.patch.object(LIVE, "stack_description", side_effect=stack):
            path = Path(directory) / "ledger.json"
            values = LIVE.bind_deployed_vapi_resources(path, ledger, {})
            self.assertEqual(values["AssistantId"], "assistant_1")
            self.assertEqual(ledger["vapi_assistant_id"], "assistant_1")
            self.assertEqual(ledger["vapi_prepare_tool_id"], "tool_1")
            self.assertEqual(ledger["vapi_webhook_credential_id"], "credential_1")
            ledger["vapi_assistant_id"] = "different"
            with self.assertRaisesRegex(LIVE.LiveTestError, "differs"):
                LIVE.bind_deployed_vapi_resources(path, ledger, {})

    def test_bound_resource_inventory_is_all_or_nothing(self):
        ledger = self.ledger()
        ledger["vapi_assistant_id"] = "assistant_1"
        with self.assertRaisesRegex(LIVE.LiveTestError, "incomplete"):
            LIVE.bound_vapi_resource_ids(ledger)

    def test_live_ownership_gate_checks_all_three_resources(self):
        ledger = self.ledger()
        stack_id = "arn:aws:cloudformation:us-west-2:123456789012:stack/vapi/uuid"
        ledger.update(
            {
                "vapi_stack_id": stack_id,
                "vapi_assistant_id": "assistant_1",
                "vapi_prepare_tool_id": "tool_1",
                "vapi_webhook_credential_id": "credential_1",
                "vapi_prepare_url": "https://handoff.example.test/prepare",
            }
        )
        owner = LIVE.hashlib.sha256(stack_id.encode()).hexdigest()[:32]
        resources = {
            "assistant": {
                "id": "assistant_1",
                "metadata": {
                    "bridgefu_recipe": LIVE.RECIPE,
                    "bridgefu_owner": owner,
                    "bridgefu_deployment": ledger["execution_id"],
                },
                "model": {"toolIds": ["tool_1"]},
                "server": {"credentialId": "credential_1"},
                "credentialIds": ["credential_1"],
            },
            "tool": {
                "id": "tool_1",
                "type": "function",
                "function": {"name": "prepare_handoff"},
                "server": {
                    "url": "https://example.test/prepare",
                    "credentialId": "credential_1",
                },
            },
            "credential": {
                "id": "credential_1",
                "provider": "custom-credential",
                "name": f"Bridgefu {owner[:30]}",
            },
        }

        def get_resource(_key, resource, _resource_id):
            return resources[resource]

        with mock.patch.object(LIVE, "vapi_get_resource", side_effect=get_resource):
            LIVE.verify_bound_vapi_resources(
                ledger, "k" * 24, {"PrepareUrl": "https://example.test/prepare"}
            )
        resources["tool"]["server"]["credentialId"] = "different"
        with mock.patch.object(LIVE, "vapi_get_resource", side_effect=get_resource):
            with self.assertRaisesRegex(LIVE.LiveTestError, "prepare-tool"):
                LIVE.verify_bound_vapi_resources(
                    ledger, "k" * 24, {"PrepareUrl": "https://example.test/prepare"}
                )

    def test_absence_proof_is_exact_and_resumable(self):
        ledger = self.ledger()
        ledger.update(
            {
                "vapi_stack_id": "arn:aws:cloudformation:vapi",
                "vapi_assistant_id": "assistant_1",
                "vapi_prepare_tool_id": "tool_1",
                "vapi_webhook_credential_id": "credential_1",
                "vapi_prepare_url": "https://handoff.example.test/prepare",
            }
        )
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            LIVE, "secret_value", return_value="k" * 24
        ) as secret, mock.patch.object(
            LIVE, "vapi_get_resource", return_value=None
        ) as get_resource:
            with mock.patch.object(
                LIVE, "vapi_owner_scan_candidates", return_value=[]
            ):
                path = Path(directory) / "ledger.json"
                LIVE.prove_bound_vapi_resources_absent(path, ledger, {})
                self.assertEqual(get_resource.call_count, 3)
                proof = json.loads(
                    (path.parent / "vapi-teardown-evidence.json").read_text()
                )
                self.assertTrue(proof["all_absent"])
                self.assertTrue(LIVE.cached_vapi_absence_proof_is_valid(path, ledger))
                secret.reset_mock()
                get_resource.reset_mock()
                LIVE.prove_bound_vapi_resources_absent(path, ledger, {})
                secret.assert_not_called()
                get_resource.assert_not_called()

    def test_absence_proof_fails_closed_when_one_resource_remains(self):
        ledger = self.ledger()
        ledger.update(
            {
                "vapi_stack_id": "arn:aws:cloudformation:vapi",
                "vapi_assistant_id": "assistant_1",
                "vapi_prepare_tool_id": "tool_1",
                "vapi_webhook_credential_id": "credential_1",
                "vapi_prepare_url": "https://handoff.example.test/prepare",
            }
        )

        def get_resource(_key, resource, resource_id):
            return {"id": resource_id} if resource == "tool" else None

        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            LIVE, "secret_value", return_value="k" * 24
        ), mock.patch.object(
            LIVE, "vapi_get_resource", side_effect=get_resource
        ), mock.patch.object(
            LIVE, "vapi_owner_scan_candidates", return_value=[]
        ), mock.patch.object(
            LIVE, "VAPI_ABSENCE_ATTEMPTS", 1
        ):
            with self.assertRaisesRegex(LIVE.LiveTestError, "left"):
                LIVE.prove_bound_vapi_resources_absent(
                    Path(directory) / "ledger.json", ledger, {}
                )

    def test_bound_absence_proof_rejects_an_owner_equivalent_duplicate(self):
        ledger = self.ledger()
        ledger.update(
            {
                "vapi_stack_id": "arn:aws:cloudformation:vapi",
                "vapi_assistant_id": "assistant_1",
                "vapi_prepare_tool_id": "tool_1",
                "vapi_webhook_credential_id": "credential_1",
                "vapi_prepare_url": "https://handoff.example.test/prepare",
            }
        )
        duplicate = {"resource": "assistant", "id": "assistant_duplicate"}
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            LIVE, "secret_value", return_value="k" * 24
        ), mock.patch.object(
            LIVE, "vapi_get_resource", return_value=None
        ), mock.patch.object(
            LIVE, "vapi_owner_scan_candidates", return_value=[duplicate]
        ), mock.patch.object(
            LIVE, "VAPI_ABSENCE_ATTEMPTS", 1
        ), self.assertRaisesRegex(LIVE.LiveTestError, "owner-derived"):
            LIVE.prove_bound_vapi_resources_absent(
                Path(directory) / "ledger.json", ledger, {}
            )

    def test_failure_before_recipe_application_is_safe_to_teardown(self):
        root_id = (
            "arn:aws:cloudformation:us-west-2:123456789012:"
            "stack/bridgefu-bft-20990101a/root"
        )
        ledger = {
            "execution_id": "bft-20990101a",
            "account_id": "123456789012",
            "partition": "aws",
            "region": "us-west-2",
            "stack_name": "bridgefu-bft-20990101a",
            "review_stack_id": root_id,
            "connect_mode": "disposable",
            "events": [{"event": "change_set_executed"}],
        }
        root = {"StackId": root_id, "StackStatus": "CREATE_FAILED"}
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            LIVE, "stack_description", return_value=root
        ), mock.patch.object(
            LIVE, "describe_exact_stack_resource_if_exists", return_value=None
        ) as describe_resource:
            path = Path(directory) / "ledger.json"
            mode = LIVE.recover_vapi_teardown_contract(
                path,
                ledger,
                {},
                application_exists=True,
                application_attempted=True,
            )
            LIVE.prove_vapi_teardown_contract(path, ledger, {})

        self.assertEqual(mode, "not_created")
        self.assertEqual(
            ledger["vapi_not_created_reason"],
            "recipe_application_has_no_physical_stack",
        )
        self.assertEqual(describe_resource.call_args.args[-1], "RecipeApplication")

    def test_in_progress_ancestor_cannot_race_not_created_classification(self):
        root_id = (
            "arn:aws:cloudformation:us-west-2:123456789012:"
            "stack/bridgefu-bft-20990101a/root"
        )
        ledger = {
            "execution_id": "bft-20990101a",
            "region": "us-west-2",
            "stack_name": "bridgefu-bft-20990101a",
            "review_stack_id": root_id,
            "connect_mode": "disposable",
            "events": [{"event": "change_set_executed"}],
        }
        root = {"StackId": root_id, "StackStatus": "CREATE_IN_PROGRESS"}
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            LIVE, "stack_description", return_value=root
        ), mock.patch.object(
            LIVE, "describe_exact_stack_resource_if_exists", return_value=None
        ) as describe_resource, self.assertRaisesRegex(
            LIVE.LiveTestError, "terminal state"
        ):
            LIVE.recover_vapi_teardown_contract(
                Path(directory) / "ledger.json",
                ledger,
                {},
                application_exists=True,
                application_attempted=True,
            )
        describe_resource.assert_not_called()
        self.assertNotIn("vapi_teardown_mode", ledger)

    def test_failed_vapi_create_uses_owner_scan_before_secret_deletion(self):
        root_id = (
            "arn:aws:cloudformation:us-west-2:123456789012:"
            "stack/bridgefu-bft-20990101a/"
            "00000000-0000-0000-0000-000000000001"
        )
        vapi_id = (
            "arn:aws:cloudformation:us-west-2:123456789012:"
            "stack/vapi/00000000-0000-0000-0000-000000000003"
        )
        handoff_id = (
            "arn:aws:cloudformation:us-west-2:123456789012:"
            "stack/handoff/00000000-0000-0000-0000-000000000004"
        )
        prepare_url = "https://handoff.example.test/prepare-handoff"
        ledger = {
            "execution_id": "bft-20990101a",
            "account_id": "123456789012",
            "partition": "aws",
            "region": "us-west-2",
            "stack_name": "bridgefu-bft-20990101a",
            "review_stack_id": root_id,
            "connect_mode": "existing",
            "vapi_api_key_secret_arn": (
                "arn:aws:secretsmanager:us-west-2:123456789012:"
                "secret:bridgefu-bft-20990101a-vapi-key"
            ),
            "events": [{"event": "change_set_executed"}],
        }
        root = {"StackId": root_id, "StackStatus": "CREATE_FAILED"}
        vapi = {
            "StackId": vapi_id,
            "ParentId": root_id,
            "RootId": root_id,
            "StackStatus": "CREATE_FAILED",
            "Outputs": [],
        }
        handoff = {
            "StackId": handoff_id,
            "ParentId": root_id,
            "RootId": root_id,
            "StackStatus": "CREATE_COMPLETE",
            "Outputs": [{"OutputKey": "PrepareUrl", "OutputValue": prepare_url}],
        }

        def resource(_ledger, _environment, _parent, logical_id):
            values = {
                "VapiResources": {
                    "LogicalResourceId": "VapiResources",
                    "ResourceStatus": "CREATE_FAILED",
                    "PhysicalResourceId": vapi_id,
                },
                "HandoffService": {
                    "LogicalResourceId": "HandoffService",
                    "ResourceStatus": "CREATE_COMPLETE",
                    "PhysicalResourceId": handoff_id,
                },
            }
            return values[logical_id]

        def stack(_ledger, _environment, stack_id):
            return {root_id: root, vapi_id: vapi, handoff_id: handoff}[stack_id]

        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            LIVE, "stack_description", side_effect=stack
        ), mock.patch.object(
            LIVE, "describe_exact_stack_resource_if_exists", side_effect=resource
        ), mock.patch.object(
            LIVE, "secret_value", return_value="k" * 24
        ), mock.patch.object(
            LIVE, "vapi_owner_scan_candidates", return_value=[]
        ) as owner_scan:
            path = Path(directory) / "ledger.json"
            mode = LIVE.recover_vapi_teardown_contract(
                path,
                ledger,
                {},
                application_exists=True,
                application_attempted=True,
            )
            LIVE.prove_vapi_teardown_contract(path, ledger, {})
            self.assertTrue(LIVE.cached_vapi_absence_proof_is_valid(path, ledger))

        self.assertEqual(mode, "owner_scan")
        self.assertEqual(ledger["vapi_stack_id"], vapi_id)
        self.assertEqual(ledger["vapi_prepare_url"], prepare_url)
        owner_scan.assert_called_once()

    def test_owner_scan_blocks_mutated_exact_name_and_prepare_url_matches(self):
        ledger = {
            "execution_id": "bft-20990101a",
            "vapi_stack_id": "arn:aws:cloudformation:vapi-stack",
            "vapi_prepare_url": "https://handoff.example.test/prepare-handoff",
        }
        expected = LIVE.vapi_owner_scan_expectation(ledger)

        def listed(_api_key, resource):
            return {
                "assistant": [
                    {
                        "id": "assistant_1",
                        "name": expected["assistant_name"],
                        "metadata": {"bridgefu_owner": "mutated"},
                    }
                ],
                "credential": [
                    {
                        "id": "credential_1",
                        "name": expected["credential_name"],
                        "provider": "mutated",
                    }
                ],
                "tool": [
                    {
                        "id": "tool_1",
                        "type": "mutated",
                        "server": {"url": expected["prepare_url"]},
                    }
                ],
            }[resource]

        with mock.patch.object(LIVE, "vapi_list_resources", side_effect=listed):
            self.assertEqual(
                LIVE.vapi_owner_scan_candidates("k" * 24, ledger),
                [
                    {"resource": "assistant", "id": "assistant_1"},
                    {"resource": "credential", "id": "credential_1"},
                    {"resource": "tool", "id": "tool_1"},
                ],
            )

    def test_owner_scan_names_match_the_provisioner_cross_contract(self):
        stack_id = (
            "arn:aws:cloudformation:us-west-2:123456789012:"
            "stack/vapi/owner-contract"
        )
        deployment_id = "bft-long_name_with_suffix"
        prepare_url = "https://handoff.example.test/prepare-handoff"
        config = ProvisioningConfig(
            stack_id=stack_id,
            deployment_id=deployment_id,
            prepare_url=prepare_url,
            transfer_url="https://handoff.example.test/transfer-destination",
            model="gpt-4.1-mini",
            voice_id="Elliot",
            webhook_token=None,
            asset_root=RECIPE_ROOT / "vapi",
        )
        expected = LIVE.vapi_owner_scan_expectation(
            {
                "execution_id": deployment_id,
                "vapi_stack_id": stack_id,
                "vapi_prepare_url": prepare_url,
            }
        )

        self.assertEqual(expected["owner_token"], config.owner_token)
        self.assertEqual(expected["assistant_name"], config.assistant_name)
        self.assertEqual(expected["credential_name"], config.credential_name)
        self.assertEqual(expected["prepare_url"], config.prepare_url)
        self.assertEqual(config.assistant_name.split()[1], "bft-long-name-wit")

    def test_destroy_orders_vapi_classification_delete_and_absence_proof(self):
        destroyer = SCRIPT.read_text().split(
            "def destroy(args: argparse.Namespace) -> None:", 1
        )[1].split("def destroy_finalize", 1)[0]
        self.assertLess(
            destroyer.index("recover_vapi_teardown_contract"),
            destroyer.index("stack_deletions ="),
        )
        self.assertLess(
            destroyer.index("stack_deletions ="),
            destroyer.index("prove_vapi_teardown_contract"),
        )
        self.assertLess(
            destroyer.index("prove_vapi_teardown_contract"),
            destroyer.index("vapi_api_key_secret_arn"),
        )

    def test_review_shell_crash_gap_requires_exact_available_change_set(self):
        root_id = (
            "arn:aws:cloudformation:us-west-2:123456789012:"
            "stack/bridgefu-bft-20990101a/"
            "00000000-0000-0000-0000-000000000001"
        )
        change_set_id = (
            "arn:aws:cloudformation:us-west-2:123456789012:changeSet/"
            "reviewed-bft-20990101a/"
            "00000000-0000-0000-0000-000000000010"
        )
        ledger = {
            "execution_id": "bft-20990101a",
            "account_id": "123456789012",
            "partition": "aws",
            "region": "us-west-2",
            "stack_name": "bridgefu-bft-20990101a",
            "review_stack_id": root_id,
            "change_set_arn": change_set_id,
            "change_set_name": "reviewed-bft-20990101a",
            "events": [{"event": "change_set_execution_requested"}],
        }
        available = {
            "ChangeSetId": change_set_id,
            "ChangeSetName": "reviewed-bft-20990101a",
            "StackId": root_id,
            "StackName": ledger["stack_name"],
            "ChangeSetType": "CREATE",
            "Status": "CREATE_COMPLETE",
            "ExecutionStatus": "AVAILABLE",
        }
        review = {"StackId": root_id, "StackStatus": "REVIEW_IN_PROGRESS"}
        with mock.patch.object(
            LIVE, "aws_json", return_value=available
        ), mock.patch.object(LIVE, "stack_description", return_value=review):
            self.assertTrue(
                LIVE.application_review_is_authoritatively_unexecuted(
                    ledger, {}, root_id
                )
            )

        in_flight = dict(available, ExecutionStatus="EXECUTE_IN_PROGRESS")
        with mock.patch.object(
            LIVE, "aws_json", return_value=in_flight
        ), mock.patch.object(LIVE, "stack_description") as stack:
            self.assertFalse(
                LIVE.application_review_is_authoritatively_unexecuted(
                    ledger, {}, root_id
                )
            )
        stack.assert_not_called()

        ledger["events"].append({"event": "change_set_executed"})
        with mock.patch.object(LIVE, "aws_json") as aws:
            self.assertFalse(
                LIVE.application_review_is_authoritatively_unexecuted(
                    ledger, {}, root_id
                )
            )
        aws.assert_not_called()

    def test_execution_intent_is_persisted_before_aws_execute(self):
        executor = SCRIPT.read_text().split(
            'if application_execution == "AVAILABLE":', 1
        )[1].split("elif ledger", 1)[0]
        self.assertLess(
            executor.index("change_set_execution_requested"),
            executor.index('"execute-change-set"'),
        )

    def test_vapi_custom_resource_has_a_bounded_service_timeout(self):
        template = (
            ROOT
            / "recipes/vapi-amazon-connect-screen-pop/cloudformation/nested/vapi.yaml"
        ).read_text()
        resource = template.split("  VapiResources:", 1)[1].split(
            "\nOutputs:", 1
        )[0]
        self.assertIn("ServiceTimeout: '300'", resource)


if __name__ == "__main__":
    unittest.main()
