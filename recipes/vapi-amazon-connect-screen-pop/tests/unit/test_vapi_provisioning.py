from __future__ import annotations

import copy
import sys
import unittest
import urllib.error
from pathlib import Path
from unittest import mock


RECIPE = Path(__file__).resolve().parents[2]
COMMON = RECIPE / "lambda" / "common"
sys.path.insert(0, str(COMMON))

from vapi_provisioning import (  # noqa: E402
    PENDING_PHYSICAL_ID,
    ProvisioningConfig,
    VapiHttpClient,
    VapiProvisioningError,
    parse_physical_id,
    provision_create,
    provision_delete,
    provision_update,
)


class FakeVapi:
    def __init__(self):
        self.resources = {"assistant": {}, "tool": {}, "credential": {}}
        self.create_count = {"assistant": 0, "tool": 0, "credential": 0}
        self.deleted = []
        self.updated_payloads = []

    def list(self, resource):
        return [copy.deepcopy(item) for item in self.resources[resource].values()]

    def get(self, resource, resource_id):
        value = self.resources[resource].get(resource_id)
        return copy.deepcopy(value) if value is not None else None

    def create(self, resource, payload):
        self.create_count[resource] += 1
        resource_id = f"{resource}_{self.create_count[resource]}"
        item = copy.deepcopy(payload)
        item["id"] = resource_id
        if resource == "credential":
            item["authenticationPlan"].pop("token", None)
        self.resources[resource][resource_id] = item
        return copy.deepcopy(item)

    def update(self, resource, resource_id, payload):
        if resource_id not in self.resources[resource]:
            raise AssertionError("updating missing fake Vapi resource")
        self.updated_payloads.append((resource, resource_id, copy.deepcopy(payload)))
        preserved = {"id": self.resources[resource][resource_id]["id"]}
        item = copy.deepcopy(payload)
        if resource == "credential":
            item["authenticationPlan"].pop("token", None)
        item.update(preserved)
        self.resources[resource][resource_id] = item
        return copy.deepcopy(item)

    def delete(self, resource, resource_id):
        self.resources[resource].pop(resource_id, None)
        self.deleted.append((resource, resource_id))


def config(**overrides):
    values = {
        "stack_id": "arn:aws:cloudformation:us-west-2:123456789012:stack/test/abc",
        "deployment_id": "bf-test-001",
        "prepare_url": "https://example.execute-api.us-west-2.amazonaws.com/v1/prepare-handoff",
        "transfer_url": "https://example.execute-api.us-west-2.amazonaws.com/v1/transfer-destination",
        "model": "gpt-4.1-mini",
        "voice_id": "Elliot",
        "webhook_token": "w" * 40,
        "asset_root": RECIPE / "vapi",
    }
    values.update(overrides)
    return ProvisioningConfig(**values)


class VapiProvisioningTests(unittest.TestCase):
    def test_http_client_retries_only_bounded_reads_with_fresh_timeouts(self):
        timeout = mock.Mock(side_effect=[3.0, 2.0])
        client = VapiHttpClient("v" * 32, request_timeout=timeout)
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.status = 200
        response.read.return_value = b"[]"
        client._opener = mock.Mock()
        client._opener.open.side_effect = [
            urllib.error.URLError("transient"),
            response,
        ]

        self.assertEqual(client.list("assistant"), [])
        self.assertTrue(
            client._opener.open.call_args_list[-1].args[0].full_url.endswith(
                "/assistant?limit=1000"
            )
        )
        self.assertEqual(timeout.call_count, 2)
        self.assertEqual(
            [call.kwargs["timeout"] for call in client._opener.open.call_args_list],
            [3.0, 2.0],
        )

    def test_http_client_never_retries_ambiguous_writes(self):
        timeout = mock.Mock(return_value=3.0)
        client = VapiHttpClient("v" * 32, request_timeout=timeout)
        client._opener = mock.Mock()
        client._opener.open.side_effect = urllib.error.URLError("transient")

        with self.assertRaisesRegex(VapiProvisioningError, "vapi_unavailable"):
            client.create("assistant", {"name": "bounded-write"})

        self.assertEqual(client._opener.open.call_count, 1)
        self.assertEqual(timeout.call_count, 1)

    def test_http_client_rejects_unbounded_timeout_and_retry_configuration(self):
        with self.assertRaisesRegex(
            VapiProvisioningError, "vapi_request_timeout_invalid"
        ):
            VapiHttpClient("v" * 32, request_timeout=lambda: 16)._timeout_seconds()
        with self.assertRaisesRegex(
            VapiProvisioningError, "vapi_retry_budget_invalid"
        ):
            VapiHttpClient("v" * 32, read_retries=2)

    def test_create_retry_is_idempotent_and_server_owned(self):
        client = FakeVapi()
        first = provision_create(client, config())
        second = provision_create(client, config())
        self.assertEqual(first, second)
        self.assertEqual(
            client.create_count,
            {"assistant": 1, "tool": 1, "credential": 1},
        )
        self.assertEqual(
            parse_physical_id(first.physical_id),
            (
                first.assistant_id,
                first.prepare_tool_id,
                first.webhook_credential_id,
            ),
        )

        assistant = client.get("assistant", first.assistant_id)
        self.assertEqual(assistant["model"]["toolIds"], [first.prepare_tool_id])
        self.assertEqual(len(assistant["model"]["tools"]), 1)
        self.assertEqual(assistant["model"]["tools"][0]["destinations"], [])
        self.assertEqual(
            assistant["server"]["credentialId"], first.webhook_credential_id
        )
        self.assertNotIn("credentials", assistant)

        credential = client.get("credential", first.webhook_credential_id)
        self.assertEqual(credential["provider"], "custom-credential")
        self.assertEqual(credential["name"], config().credential_name)
        self.assertEqual(credential["authenticationPlan"]["type"], "bearer")
        self.assertNotIn("token", credential["authenticationPlan"])

        tool = client.get("tool", first.prepare_tool_id)
        self.assertEqual(tool["function"]["name"], "prepare_handoff")
        self.assertEqual(
            tool["server"]["credentialId"], first.webhook_credential_id
        )
        schema = tool["function"]["parameters"]
        self.assertNotIn("route", schema["properties"])
        self.assertNotIn("sipUri", schema["properties"])

    def test_update_preserves_ids_and_changes_only_owned_configuration(self):
        client = FakeVapi()
        old = config()
        created = provision_create(client, old)
        new = config(
            prepare_url="https://new.example.test/v1/prepare-handoff",
            transfer_url="https://new.example.test/v1/transfer-destination",
            model="gpt-4.1",
        )
        updated = provision_update(client, old, new, created.physical_id)
        self.assertEqual(created, updated)
        self.assertEqual(
            client.create_count,
            {"assistant": 1, "tool": 1, "credential": 1},
        )
        assistant = client.get("assistant", created.assistant_id)
        tool = client.get("tool", created.prepare_tool_id)
        self.assertEqual(assistant["model"]["model"], "gpt-4.1")
        self.assertEqual(assistant["server"]["url"], new.transfer_url)
        self.assertEqual(tool["server"]["url"], new.prepare_url)
        credential_updates = [
            payload
            for resource, resource_id, payload in client.updated_payloads
            if resource == "credential"
            and resource_id == created.webhook_credential_id
        ]
        self.assertEqual(credential_updates[-1]["authenticationPlan"]["token"], "w" * 40)

    def test_conflicting_unowned_assistant_fails_closed(self):
        client = FakeVapi()
        desired = config()
        client.resources["assistant"]["assistant_attacker"] = {
            "id": "assistant_attacker",
            "name": desired.assistant_name,
            "metadata": {"bridgefu_owner": "someone-else"},
            "credentialIds": ["credential_attacker"],
        }
        with self.assertRaisesRegex(
            VapiProvisioningError, "vapi_assistant_ownership_conflict"
        ):
            provision_create(client, desired)
        self.assertEqual(
            client.create_count,
            {"assistant": 0, "tool": 0, "credential": 0},
        )

    def test_conflicting_named_credential_fails_closed(self):
        client = FakeVapi()
        desired = config()
        client.resources["credential"]["credential_attacker"] = {
            "id": "credential_attacker",
            "name": desired.credential_name,
            "provider": "custom-credential",
            "authenticationPlan": {
                "type": "bearer",
                "headerName": "X-Not-Bridgefu",
                "bearerPrefixEnabled": False,
            },
        }
        with self.assertRaisesRegex(
            VapiProvisioningError, "vapi_credential_ownership_conflict"
        ):
            provision_create(client, desired)
        self.assertEqual(client.create_count["assistant"], 0)
        self.assertEqual(client.create_count["credential"], 0)

    def test_delete_verifies_attachment_and_ownership(self):
        client = FakeVapi()
        desired = config()
        created = provision_create(client, desired)
        provision_delete(
            client,
            config(webhook_token=None),
            created.physical_id,
        )
        self.assertEqual(
            client.resources,
            {"assistant": {}, "tool": {}, "credential": {}},
        )
        self.assertEqual(
            client.deleted,
            [
                ("assistant", created.assistant_id),
                ("tool", created.prepare_tool_id),
                ("credential", created.webhook_credential_id),
            ],
        )

        created = provision_create(client, desired)
        client.resources["assistant"][created.assistant_id]["model"]["toolIds"] = []
        with self.assertRaisesRegex(
            VapiProvisioningError, "vapi_prepare_tool_ownership_conflict"
        ):
            provision_delete(client, desired, created.physical_id)
        self.assertIn(created.assistant_id, client.resources["assistant"])
        self.assertIn(created.prepare_tool_id, client.resources["tool"])

    def test_pending_delete_discovers_partial_or_complete_owned_resources(self):
        client = FakeVapi()
        desired = config()
        created = provision_create(client, desired)

        provision_delete(client, desired, PENDING_PHYSICAL_ID)
        provision_delete(client, desired, PENDING_PHYSICAL_ID)

        self.assertEqual(
            client.resources,
            {"assistant": {}, "tool": {}, "credential": {}},
        )
        self.assertIn(("assistant", created.assistant_id), client.deleted)
        self.assertIn(("tool", created.prepare_tool_id), client.deleted)
        self.assertIn(("credential", created.webhook_credential_id), client.deleted)

    def test_pending_delete_handles_assistant_created_before_credential(self):
        client = FakeVapi()
        desired = config()
        client.resources["assistant"]["assistant_partial"] = {
            "id": "assistant_partial",
            "name": desired.assistant_name,
            "metadata": desired.metadata,
            "server": {"url": desired.transfer_url},
            "model": {"tools": []},
        }

        provision_delete(client, desired, PENDING_PHYSICAL_ID)

        self.assertEqual(client.resources["assistant"], {})
        self.assertEqual(client.deleted, [("assistant", "assistant_partial")])

    def test_pending_delete_retry_finishes_after_assistant_was_deleted(self):
        client = FakeVapi()
        desired = config()
        created = provision_create(client, desired)
        client.resources["assistant"].pop(created.assistant_id)

        provision_delete(client, desired, PENDING_PHYSICAL_ID)

        self.assertEqual(
            client.resources,
            {"assistant": {}, "tool": {}, "credential": {}},
        )
        self.assertEqual(
            client.deleted,
            [
                ("tool", created.prepare_tool_id),
                ("credential", created.webhook_credential_id),
            ],
        )

    def test_nonpending_delete_also_removes_owner_equivalent_duplicates(self):
        client = FakeVapi()
        desired = config()
        created = provision_create(client, desired)
        duplicate_assistant = copy.deepcopy(
            client.resources["assistant"][created.assistant_id]
        )
        duplicate_tool = copy.deepcopy(client.resources["tool"][created.prepare_tool_id])
        duplicate_credential = copy.deepcopy(
            client.resources["credential"][created.webhook_credential_id]
        )
        duplicate_assistant.update(
            {
                "id": "assistant_duplicate",
                "credentialIds": ["credential_duplicate"],
            }
        )
        duplicate_assistant["server"]["credentialId"] = "credential_duplicate"
        duplicate_assistant["model"]["toolIds"] = ["tool_duplicate"]
        duplicate_tool["id"] = "tool_duplicate"
        duplicate_tool["server"]["credentialId"] = "credential_duplicate"
        duplicate_credential["id"] = "credential_duplicate"
        client.resources["assistant"]["assistant_duplicate"] = duplicate_assistant
        client.resources["tool"]["tool_duplicate"] = duplicate_tool
        client.resources["credential"]["credential_duplicate"] = duplicate_credential

        provision_delete(client, desired, created.physical_id)

        self.assertEqual(
            client.resources,
            {"assistant": {}, "tool": {}, "credential": {}},
        )
        self.assertIn(("assistant", "assistant_duplicate"), client.deleted)
        self.assertIn(("tool", "tool_duplicate"), client.deleted)
        self.assertIn(("credential", "credential_duplicate"), client.deleted)

    def test_http_client_refuses_a_full_owner_scan_page(self):
        client = VapiHttpClient("v" * 32)
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.status = 200
        response.read.return_value = ("[" + ",".join("{}" for _ in range(1000)) + "]").encode()
        client._opener = mock.Mock()
        client._opener.open.return_value = response

        with self.assertRaisesRegex(VapiProvisioningError, "vapi_response_invalid"):
            client.list("credential")

    def test_pending_delete_removes_owned_assistant_without_touching_collision(self):
        client = FakeVapi()
        desired = config()
        client.resources["assistant"]["assistant_partial"] = {
            "id": "assistant_partial",
            "name": desired.assistant_name,
            "metadata": desired.metadata,
            "server": {"url": desired.transfer_url},
            "model": {"tools": []},
        }
        client.resources["credential"]["credential_external"] = {
            "id": "credential_external",
            "name": desired.credential_name,
            "provider": "custom-credential",
            "authenticationPlan": {
                "type": "bearer",
                "headerName": "X-External",
                "bearerPrefixEnabled": False,
            },
        }

        provision_delete(client, desired, PENDING_PHYSICAL_ID)

        self.assertEqual(client.resources["assistant"], {})
        self.assertIn("credential_external", client.resources["credential"])
        self.assertEqual(client.deleted, [("assistant", "assistant_partial")])

    def test_invalid_nonpending_physical_id_still_fails_closed(self):
        with self.assertRaisesRegex(
            VapiProvisioningError, "vapi_physical_id_invalid"
        ):
            provision_delete(FakeVapi(), config(), "not-a-bridgefu-id")

    def test_v1_physical_id_remains_delete_compatible(self):
        client = FakeVapi()
        desired = config()
        created = provision_create(client, desired)
        legacy_id = (
            f"bridgefu-vapi-v1:{created.assistant_id}:{created.prepare_tool_id}"
        )

        provision_delete(client, desired, legacy_id)

        self.assertEqual(
            client.resources,
            {"assistant": {}, "tool": {}, "credential": {}},
        )


if __name__ == "__main__":
    unittest.main()
