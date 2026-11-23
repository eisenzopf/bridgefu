import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
import yaml
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "shared"))
import render
import handler


class FakeConditional(Exception):
    pass


class FakeTable:
    def __init__(self):
        self.items = {}
        self.meta = type(
            "Meta",
            (),
            {
                "client": type(
                    "Client",
                    (),
                    {
                        "exceptions": type(
                            "Errors",
                            (),
                            {"ConditionalCheckFailedException": FakeConditional},
                        )
                    },
                )
            },
        )

    def put_item(self, Item, **kwargs):
        if Item["id"] in self.items:
            raise FakeConditional()
        self.items[Item["id"]] = copy.deepcopy(Item)

    def get_item(self, Key, **kwargs):
        return {"Item": self.items.get(Key["id"], {})}


class Examples(unittest.TestCase):
    def settings(self, mode="sip-headers"):
        return json.loads((ROOT / mode / "settings.example.json").read_text())

    def test_custom_fields_generate_every_contract(self):
        for mode in ("sip-headers", "correlation-id"):
            c = self.settings(mode)
            c["fields"] = [
                {
                    "name": "ticket",
                    "source": "arguments.ticket",
                    "header": "X-My-Ticket",
                    "attribute": "my_ticket",
                    "description": "Your chosen ticket",
                    "max_bytes": 100,
                    "required": True,
                }
            ]
            c["correlation"] = {
                "header": "X-My-Lookup",
                "attribute": "lookup_token",
                "ttl_seconds": 900,
            }
            with tempfile.TemporaryDirectory() as d:
                gateway = render.render(c, d)
                assistant = json.loads((Path(d) / "vapi/assistant.json").read_text())
                self.assertEqual(
                    list(
                        assistant["model"]["tools"][0]["function"]["parameters"][
                            "properties"
                        ]
                    ),
                    ["ticket"],
                )
                self.assertEqual(
                    gateway["context"]["allow_headers"],
                    {"X-My-Ticket": "my_ticket"}
                    if mode == "sip-headers"
                    else {"X-My-Lookup": "lookup_token"},
                )
                template = render.template(c, render.validate(c))
                self.assertEqual(
                    "ContextTable" in template["Resources"], mode == "correlation-id"
                )
                self.assertEqual(
                    "LookupFunction" in template["Resources"], mode == "correlation-id"
                )
                if mode == "correlation-id":
                    self.assertIn("$.External.my_ticket", json.dumps(render.flow(c)))

    def test_cloudformation_has_no_aliases_and_matches_lambda_source(self):
        for mode in ("sip-headers", "correlation-id"):
            with tempfile.TemporaryDirectory() as directory:
                render.render(self.settings(mode), directory)
                text = (
                    Path(directory) / "amazon-connect/cloudformation.yaml"
                ).read_text()
                self.assertFalse(
                    any(
                        isinstance(event, yaml.AliasEvent) for event in yaml.parse(text)
                    )
                )
                resources = yaml.safe_load(text)["Resources"]
                for resource in resources.values():
                    if resource["Type"] == "AWS::Lambda::Function":
                        self.assertEqual(
                            resource["Properties"]["Code"]["ZipFile"],
                            (ROOT / "shared/handler.py").read_text(),
                        )

    def test_duplicate_reserved_and_oversized_configuration_rejected(self):
        for change in (
            lambda c: c["fields"].append(copy.deepcopy(c["fields"][0])),
            lambda c: c["fields"][0].update(attribute="tenant_id"),
            lambda c: c["fields"][0].update(header="X-Test\r\nInjected"),
            lambda c: c["fields"][0].update(max_bytes=9999),
        ):
            c = self.settings()
            change(c)
            with self.assertRaises(ValueError):
                render.validate(c)

    def test_nested_input_path_matches_transfer_reader(self):
        c = self.settings()
        c["fields"][0]["source"] = "variables.account.session"
        supplied = render.variable_examples(c)
        call = {
            "id": "synthetic-call",
            "assistantOverrides": {"variableValues": supplied},
        }
        values = handler.values_for(
            c, call, {"intent": "help", "summary": "Needs support."}
        )
        self.assertEqual(values["customer_session"], c["fields"][0]["example"])
        self.assertEqual(supplied["account"]["session"], c["fields"][0]["example"])

    def test_identity_is_not_taken_from_model_arguments(self):
        c = self.settings()
        call = {
            "id": "synthetic-call",
            "assistantOverrides": {"variableValues": {"customer_session": "00000123"}},
        }
        values = handler.values_for(
            c,
            call,
            {
                "session": "forged",
                "vapi_reference": "forged",
                "intent": "help",
                "summary": "Asked for support.",
            },
        )
        self.assertEqual(values["customer_session"], "00000123")
        self.assertEqual(values["vapi_reference"], "synthetic-call")
        for bad in ("x\r\nX-Evil: y", "x" * 513, "{{missing}}"):
            with self.assertRaises(ValueError):
                handler.values_for(c, call, {"intent": "help", "summary": bad})
        with self.assertRaises(ValueError):
            handler.values_for(
                c, {"id": "synthetic-call"}, {"intent": "help", "summary": "summary"}
            )

    def test_header_only_has_no_lookup(self):
        c = self.settings()
        vals = {f["attribute"]: "synthetic" for f in c["fields"]}
        with patch.dict(
            os.environ,
            {"GATEWAY_SIP_URI": "sips:support@example.test:5061;transport=tls"},
        ):
            dest = handler.destination(c, vals, "call", "tool", "secret")
        self.assertEqual(set(dest["sipHeaders"]), {f["header"] for f in c["fields"]})
        self.assertNotIn("X-Correlation-Id", dest["sipHeaders"])

    def test_store_lookup_expiration_and_retry(self):
        c = self.settings("correlation-id")
        table = FakeTable()
        resource = type("Resource", (), {"Table": lambda self, name: table})()
        vals = {f["attribute"]: "synthetic" for f in c["fields"]}
        env = {
            "GATEWAY_SIP_URI": "sips:support@example.test:5061;transport=tls",
            "CONTEXT_TABLE": "test",
            "FIELD_CONFIG": json.dumps(c),
            "CONNECT_INSTANCE_ARN": "synthetic-instance",
        }
        with (
            patch.dict(os.environ, env),
            patch.object(handler.boto3, "resource", return_value=resource),
        ):
            d = handler.destination(c, vals, "call", "tool", "test-secret")
            self.assertEqual(
                handler.destination(c, vals, "call", "tool", "test-secret"), d
            )
            with self.assertRaises(ValueError):
                handler.destination(
                    c,
                    {**vals, "customer_intent": "changed"},
                    "call",
                    "tool",
                    "test-secret",
                )
            token = d["sipHeaders"]["X-Correlation-Id"]
            self.assertEqual(len(d["sipHeaders"]), 1)
            event = {
                "Details": {
                    "ContactData": {
                        "InstanceARN": "synthetic-instance",
                        "Attributes": {"handoff_id": token},
                    }
                }
            }
            self.assertEqual(
                handler.lookup(event, None), {**vals, "handoff_status": "found"}
            )
            table.items[token]["expires_at"] = 0
            self.assertEqual(
                handler.lookup(event, None), {"handoff_status": "expired_or_missing"}
            )
            event["Details"]["ContactData"]["InstanceARN"] = "other"
            self.assertEqual(
                handler.lookup(event, None), {"handoff_status": "invalid_instance"}
            )

    def test_unauthenticated_webhook_never_calls_vapi(self):
        with (
            patch.dict(os.environ, {"WEBHOOK_SECRET_ARN": "test"}),
            patch.object(handler, "secret", return_value="expected"),
            patch.object(handler, "api") as api,
        ):
            self.assertEqual(
                handler.transfer({"headers": {}, "body": "{}"}, None)["statusCode"], 401
            )
            api.assert_not_called()


if __name__ == "__main__":
    unittest.main()
