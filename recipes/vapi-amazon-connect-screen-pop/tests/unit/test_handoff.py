from __future__ import annotations

import base64
import json
import sys
import unittest
from pathlib import Path


COMMON = Path(__file__).resolve().parents[2] / "lambda" / "common"
sys.path.insert(0, str(COMMON))

from bridgefu_handoff import (  # noqa: E402
    CORRELATION_HEADER,
    HandoffError,
    SipReservation,
    VapiIdentity,
    connect_lookup,
    decode_http_json,
    derive_correlation_id,
    prepare_handoff,
    prepare_vapi_response,
    direct_transfer_response,
    transfer_destination,
    vapi_control_url,
    verify_bearer,
    verify_vapi_binding,
)
from screen_pop import parse_fields, schema_hash, vapi_parameters  # noqa: E402


KEY = b"correlation-key-is-distinct-and-at-least-32-bytes"
DEPLOYMENT = "recipe-test"
NOW = 1_800_000_000


def prepare_event(**overrides):
    values = {
        "customer_name": "Ada Lovelace",
        "issue_summary": "Needs help with a disputed order.",
        "intent": "order_dispute",
        "verification_status": "verified",
    }
    values.update(overrides)
    return {
        "message": {
            "type": "tool-calls",
            "call": {
                "id": "call_test_001",
                "orgId": "org_test_001",
                "assistantId": "assistant_test_001",
            },
            "toolCallList": [
                {
                    "id": "tool_test_001",
                    "name": "prepare_handoff",
                    "arguments": values,
                }
            ],
        }
    }


def current_prepare_event(**overrides):
    event = prepare_event(**overrides)
    tool_call = event["message"]["toolCallList"][0]
    return {
        "message": {
            **event["message"],
            "toolCallList": [
                {
                    "id": tool_call["id"],
                    "type": "function",
                    "function": {
                        "name": tool_call["name"],
                        "arguments": json.dumps(
                            tool_call["arguments"], separators=(",", ":")
                        ),
                    },
                }
            ],
        }
    }


def transfer_event(**extra):
    message = {
        "type": "transfer-destination-request",
        "call": {
            "id": "call_test_001",
            "orgId": "org_test_001",
            "assistantId": "assistant_test_001",
        },
    }
    message.update(extra)
    return {"message": message}


class FakeStore:
    def __init__(self):
        self.records = {}
        self.reserve_updates = 0

    def put_prepared(self, record):
        existing = self.records.get(record["correlation_id"])
        if existing is None:
            self.records[record["correlation_id"]] = dict(record)
            return "created"
        if (
            existing["content_hash"] == record["content_hash"]
            and existing["vapi_call_fingerprint"] == record["vapi_call_fingerprint"]
            and existing["handoff_status"] in ("PREPARED", "RESERVED")
        ):
            return "replayed"
        raise HandoffError("handoff_replay_conflict", 409)

    def get(self, correlation_id):
        record = self.records.get(correlation_id)
        return dict(record) if record is not None else None

    def mark_reserved(
        self,
        correlation_id,
        updated_at,
        bridgefu_call_id,
        attachment_expires_at,
    ):
        record = self.records[correlation_id]
        if record["handoff_status"] not in ("PREPARED", "RESERVED"):
            raise HandoffError("handoff_state_conflict", 409)
        record.update(
            handoff_status="RESERVED",
            updated_at=updated_at,
            bridgefu_call_id=bridgefu_call_id,
            attachment_expires_at=attachment_expires_at,
        )
        self.reserve_updates += 1


class HandoffContractTests(unittest.TestCase):
    def test_correlation_is_deterministic_opaque_and_versioned(self):
        identity = VapiIdentity("org_test_001", "call_test_001")
        first = derive_correlation_id(KEY, DEPLOYMENT, identity)
        self.assertEqual(first, derive_correlation_id(KEY, DEPLOYMENT, identity))
        self.assertRegex(first, r"^bf1_[A-Za-z0-9_-]{43}$")
        self.assertNotIn(identity.call_id, first)
        self.assertNotEqual(
            first,
            derive_correlation_id(KEY, "another-deployment", identity),
        )

    def test_prepare_is_bounded_idempotent_and_hides_correlation_from_model(self):
        store = FakeStore()
        created = prepare_handoff(
            prepare_event(), store, KEY, DEPLOYMENT, 86_400, now=NOW
        )
        replayed = prepare_handoff(
            prepare_event(), store, KEY, DEPLOYMENT, 86_400, now=NOW + 5
        )
        self.assertFalse(created.replayed)
        self.assertTrue(replayed.replayed)
        self.assertEqual(created.correlation_id, replayed.correlation_id)
        self.assertEqual(len(store.records), 1)
        response = prepare_vapi_response(created)
        self.assertEqual(
            response,
            {
                "results": [
                    {
                        "toolCallId": "tool_test_001",
                        "result": "prepared",
                    }
                ]
            },
        )
        self.assertNotIn(created.correlation_id, json.dumps(response))
        record = store.records[created.correlation_id]
        self.assertEqual(record["handoff_status"], "PREPARED")
        self.assertEqual(record["expires_at"], NOW + 86_400)
        self.assertNotIn("transcript", record)

    def test_prepare_accepts_current_nested_string_arguments(self):
        store = FakeStore()
        prepared = prepare_handoff(
            current_prepare_event(), store, KEY, DEPLOYMENT, 86_400, now=NOW
        )
        self.assertFalse(prepared.replayed)
        self.assertEqual(len(store.records), 1)
        record = store.records[prepared.correlation_id]
        self.assertEqual(record["customer_name"], "Ada Lovelace")
        self.assertEqual(record["intent"], "order_dispute")

    def test_prepare_rejects_ambiguous_or_malformed_current_tool_calls(self):
        ambiguous = current_prepare_event()
        ambiguous_call = ambiguous["message"]["toolCallList"][0]
        ambiguous_call["name"] = "prepare_handoff"
        malformed = current_prepare_event()
        malformed["message"]["toolCallList"][0]["function"]["arguments"] = "{"
        duplicate = current_prepare_event()
        duplicate["message"]["toolCallList"][0]["function"]["arguments"] = (
            '{"customer_name":"Ada","customer_name":"Grace",'
            '"issue_summary":"Issue","intent":"help",'
            '"verification_status":"verified"}'
        )
        wrong_type = current_prepare_event()
        wrong_type["message"]["toolCallList"][0]["type"] = "transferCall"
        for event in (ambiguous, malformed, duplicate, wrong_type):
            with self.assertRaises(HandoffError):
                prepare_handoff(event, FakeStore(), KEY, DEPLOYMENT, 86_400, now=NOW)

    def test_prepare_rejects_conflicting_replay_unknown_fields_and_controls(self):
        store = FakeStore()
        prepare_handoff(prepare_event(), store, KEY, DEPLOYMENT, 86_400, now=NOW)
        with self.assertRaisesRegex(HandoffError, "handoff_replay_conflict"):
            prepare_handoff(
                prepare_event(issue_summary="Different content"),
                store,
                KEY,
                DEPLOYMENT,
                86_400,
                now=NOW,
            )
        for event in (
            prepare_event(extra="not allowed"),
            prepare_event(customer_name="bad\nname"),
            prepare_event(issue_summary="x" * 1025),
        ):
            with self.assertRaises(HandoffError):
                prepare_handoff(event, FakeStore(), KEY, DEPLOYMENT, 86_400, now=NOW)

    def test_transfer_uses_only_fixed_route_output_and_one_header(self):
        store = FakeStore()
        prepared = prepare_handoff(
            prepare_event(), store, KEY, DEPLOYMENT, 86_400, now=NOW
        )
        observed = {}

        def reserve(correlation_id, idempotency_key):
            observed.update(
                correlation_id=correlation_id,
                idempotency_key=idempotency_key,
            )
            return SipReservation(
                uri="sips:one-use-token@sip.example.test:5061;transport=tls",
                call_id="018f4d41-0000-7000-8000-000000000001",
                expires_at=NOW + 120,
            )

        response = transfer_destination(
            transfer_event(
                route="attacker-route",
                sipUri="sip:attacker.invalid",
                sipHeaders={"Authorization": "leak"},
            ),
            store,
            KEY,
            DEPLOYMENT,
            reserve,
            "sips",
            now=NOW,
        )
        self.assertEqual(observed["correlation_id"], prepared.correlation_id)
        self.assertTrue(observed["idempotency_key"].startswith("vapi-transfer-"))
        destination = response["destination"]
        self.assertEqual(destination["type"], "sip")
        self.assertEqual(
            destination["sipUri"],
            "sips:one-use-token@sip.example.test:5061;transport=tls",
        )
        self.assertEqual(
            destination["sipHeaders"],
            {CORRELATION_HEADER: prepared.correlation_id},
        )
        self.assertEqual(store.reserve_updates, 1)

    def test_transfer_rejects_missing_expired_identity_and_scheme_conflicts(self):
        with self.assertRaisesRegex(HandoffError, "handoff_not_prepared"):
            transfer_destination(
                transfer_event(),
                FakeStore(),
                KEY,
                DEPLOYMENT,
                lambda *_: None,
                "sips",
                now=NOW,
            )
        store = FakeStore()
        prepared = prepare_handoff(
            prepare_event(), store, KEY, DEPLOYMENT, 300, now=NOW
        )
        with self.assertRaisesRegex(HandoffError, "handoff_expired"):
            transfer_destination(
                transfer_event(),
                store,
                KEY,
                DEPLOYMENT,
                lambda *_: None,
                "sips",
                now=NOW + 301,
            )
        store.records[prepared.correlation_id]["expires_at"] = NOW + 600
        store.records[prepared.correlation_id]["vapi_call_fingerprint"] = "0" * 64
        with self.assertRaisesRegex(HandoffError, "handoff_identity_conflict"):
            transfer_destination(
                transfer_event(),
                store,
                KEY,
                DEPLOYMENT,
                lambda *_: None,
                "sips",
                now=NOW,
            )
        store.records[prepared.correlation_id]["vapi_call_fingerprint"] = next(
            iter(FakeStoreFromEvent().records.values())
        )["vapi_call_fingerprint"]
        with self.assertRaisesRegex(HandoffError, "bridgefu_destination_invalid"):
            transfer_destination(
                transfer_event(),
                store,
                KEY,
                DEPLOYMENT,
                lambda *_: SipReservation(
                    "sip:clear@example.test:5060",
                    "018f4d41-0000-7000-8000-000000000001",
                    NOW + 120,
                ),
                "sips",
                now=NOW,
            )

    def test_connect_lookup_returns_only_fixed_flat_strings_and_fails_open(self):
        store = FakeStore()
        prepared = prepare_handoff(
            prepare_event(), store, KEY, DEPLOYMENT, 86_400, now=NOW
        )
        event = {
            "Details": {
                "ContactData": {
                    "Attributes": {"correlation_id": prepared.correlation_id}
                }
            }
        }
        available = connect_lookup(event, store, now=NOW)
        self.assertEqual(available["context_available"], "true")
        self.assertEqual(
            set(available),
            {
                "context_available",
                "routing_value",
                "customer_name",
                "issue_summary",
                "intent",
                "verification_status",
                "vapi_call_reference",
            },
        )
        self.assertTrue(all(isinstance(value, str) for value in available.values()))
        self.assertEqual(available["routing_value"], "")
        self.assertNotIn(prepared.correlation_id, available.values())
        self.assertEqual(
            connect_lookup({}, store, now=NOW)["context_available"], "false"
        )
        store.records[prepared.correlation_id]["expires_at"] = NOW
        self.assertEqual(
            connect_lookup(event, store, now=NOW)["context_available"], "false"
        )

    def test_http_auth_and_body_contract(self):
        secret = "v" * 32
        verify_bearer({"Authorization": f"Bearer {secret}"}, secret)
        for headers in (
            {},
            {"authorization": "Bearer wrong"},
            {"Authorization": f"Bearer {secret}", "authorization": f"Bearer {secret}"},
        ):
            with self.assertRaisesRegex(HandoffError, "unauthorized"):
                verify_bearer(headers, secret)
        body = json.dumps(prepare_event())
        decoded, _ = decode_http_json(
            {
                "headers": {"Content-Type": "application/json; charset=utf-8"},
                "body": base64.b64encode(body.encode()).decode(),
                "isBase64Encoded": True,
            }
        )
        self.assertEqual(decoded, prepare_event())
        with self.assertRaisesRegex(HandoffError, "unsupported_content_type"):
            decode_http_json(
                {
                    "headers": {"content-type": "text/plain"},
                    "body": body,
                    "isBase64Encoded": False,
                }
            )

    def test_vapi_binding_rejects_another_org_or_assistant(self):
        binding = {
            "status": "bound",
            "organization_id": "org_test_001",
            "assistant_id": "assistant_test_001",
        }
        verify_vapi_binding(prepare_event(), binding)
        verify_vapi_binding(prepare_event(), {"status": "unbound"})
        wrong_org = prepare_event()
        wrong_org["message"]["call"]["orgId"] = "org_attacker"
        wrong_assistant = prepare_event()
        wrong_assistant["message"]["call"]["assistantId"] = "assistant_attacker"
        for event in (wrong_org, wrong_assistant):
            with self.assertRaisesRegex(HandoffError, "vapi_identity_mismatch"):
                verify_vapi_binding(event, binding)
        with self.assertRaisesRegex(HandoffError, "vapi_identity_binding_invalid"):
            verify_vapi_binding(prepare_event(), {"status": "bound"})

    def test_configurable_text_and_choice_schema_round_trips_as_v2_slots(self):
        fields = parse_fields(
            [
                {
                    "key": "customer_name",
                    "label": "Customer",
                    "description": "Caller name.",
                    "type": "text",
                    "required": True,
                    "max_length": 80,
                },
                {
                    "key": "priority",
                    "label": "Priority",
                    "description": "Support priority.",
                    "type": "choice",
                    "required": True,
                    "choices": ["normal", "urgent"],
                },
                {
                    "key": "case_note",
                    "label": "Case note",
                    "description": "Optional case note.",
                    "type": "text",
                    "required": False,
                    "max_length": 256,
                },
            ]
        )
        event = prepare_event()
        call = event["message"]["toolCallList"][0]
        call["name"] = "prepare_bridgefu_amazon_connect_transfer"
        call["arguments"] = {
            "customer_name": "Ada Lovelace",
            "priority": "urgent",
        }
        store = FakeStore()
        prepared = prepare_handoff(
            event,
            store,
            KEY,
            DEPLOYMENT,
            3_600,
            now=NOW,
            configured_fields=fields,
        )
        record = store.records[prepared.correlation_id]
        self.assertEqual(record["schema_version"], 2)
        self.assertEqual(record["screen_pop_schema_hash"], schema_hash(fields))
        self.assertEqual(
            record["screen_pop_values"],
            {
                "customer_name": "Ada Lovelace",
                "priority": "urgent",
                "case_note": "",
            },
        )
        lookup = connect_lookup(
            {
                "Details": {
                    "ContactData": {
                        "Attributes": {"correlation_id": prepared.correlation_id}
                    }
                }
            },
            store,
            now=NOW,
            configured_fields=fields,
        )
        self.assertEqual(lookup["context_available"], "true")
        self.assertEqual(lookup["screen_pop_label_1"], "Customer")
        self.assertEqual(lookup["screen_pop_value_1"], "Ada Lovelace")
        self.assertEqual(lookup["screen_pop_label_2"], "Priority")
        self.assertEqual(lookup["screen_pop_value_2"], "urgent")
        self.assertEqual(lookup["screen_pop_label_3"], "Case note")
        self.assertEqual(lookup["screen_pop_value_3"], "")
        self.assertEqual(lookup["routing_value"], "")
        routed = connect_lookup(
            {
                "Details": {
                    "ContactData": {
                        "Attributes": {"correlation_id": prepared.correlation_id}
                    }
                }
            },
            store,
            now=NOW,
            configured_fields=fields,
            routing_field_key="priority",
        )
        self.assertEqual(routed["routing_value"], "urgent")
        self.assertEqual(routed["context_available"], "true")
        self.assertEqual(
            connect_lookup(
                {
                    "Details": {
                        "ContactData": {
                            "Attributes": {"correlation_id": prepared.correlation_id}
                        }
                    }
                },
                store,
                now=NOW,
                configured_fields=fields,
                routing_field_key="customer_name",
            )["context_available"],
            "false",
        )
        schema = vapi_parameters(fields)
        self.assertEqual(schema["properties"]["priority"]["enum"], ["normal", "urgent"])
        self.assertNotIn("case_note", schema["required"])

    def test_configurable_values_reject_invalid_choice_missing_required_and_conflict(self):
        fields = parse_fields(
            [
                {
                    "key": "priority",
                    "label": "Priority",
                    "description": "Support priority.",
                    "type": "choice",
                    "required": True,
                    "choices": ["normal", "urgent"],
                }
            ]
        )

        def event(arguments):
            value = prepare_event()
            call = value["message"]["toolCallList"][0]
            call["name"] = "prepare_bridgefu_amazon_connect_transfer"
            call["arguments"] = arguments
            return value

        for invalid in ({}, {"priority": "invalid"}, {"priority": "urgent", "extra": "x"}):
            with self.assertRaises(HandoffError):
                prepare_handoff(
                    event(invalid),
                    FakeStore(),
                    KEY,
                    DEPLOYMENT,
                    3_600,
                    now=NOW,
                    configured_fields=fields,
                )
        store = FakeStore()
        first = prepare_handoff(
            event({"priority": "urgent"}),
            store,
            KEY,
            DEPLOYMENT,
            3_600,
            now=NOW,
            configured_fields=fields,
        )
        self.assertTrue(
            prepare_handoff(
                event({"priority": "urgent"}),
                store,
                KEY,
                DEPLOYMENT,
                3_600,
                now=NOW + 1,
                configured_fields=fields,
            ).replayed
        )
        with self.assertRaisesRegex(HandoffError, "handoff_replay_conflict"):
            prepare_handoff(
                event({"priority": "normal"}),
                store,
                KEY,
                DEPLOYMENT,
                3_600,
                now=NOW + 2,
                configured_fields=fields,
            )
        self.assertNotIn(first.correlation_id, json.dumps(direct_transfer_response(first)))

    def test_optional_choice_can_be_omitted_and_routes_to_default(self):
        fields = parse_fields(
            [
                {
                    "key": "queue",
                    "label": "Queue",
                    "description": "Reviewed support route.",
                    "type": "choice",
                    "required": False,
                    "choices": ["sales", "support"],
                }
            ]
        )
        event = prepare_event()
        call = event["message"]["toolCallList"][0]
        call["name"] = "prepare_bridgefu_amazon_connect_transfer"
        call["arguments"] = {}
        store = FakeStore()
        prepared = prepare_handoff(
            event,
            store,
            KEY,
            DEPLOYMENT,
            3_600,
            now=NOW,
            configured_fields=fields,
        )
        lookup = connect_lookup(
            {
                "Details": {
                    "ContactData": {
                        "Attributes": {"correlation_id": prepared.correlation_id}
                    }
                }
            },
            store,
            now=NOW,
            configured_fields=fields,
            routing_field_key="queue",
        )
        self.assertEqual(lookup["context_available"], "true")
        self.assertEqual(lookup["routing_value"], "")

    def test_vapi_control_url_rejects_ssrf_and_accepts_only_vapi_https(self):
        event = prepare_event()
        event["message"]["call"]["monitor"] = {
            "controlUrl": "https://api.vapi.ai/call/control"
        }
        self.assertEqual(
            vapi_control_url(event), "https://api.vapi.ai/call/control"
        )
        for invalid in (
            "http://api.vapi.ai/control",
            "https://api.vapi.ai@example.invalid/control",
            "https://example.invalid/control",
            "https://api.vapi.ai/control?token=secret",
            "https://api.vapi.ai/../admin",
        ):
            event["message"]["call"]["monitor"]["controlUrl"] = invalid
            with self.assertRaisesRegex(HandoffError, "vapi_control_url_invalid"):
                vapi_control_url(event)


class FakeStoreFromEvent(FakeStore):
    def __init__(self):
        super().__init__()
        prepare_handoff(prepare_event(), self, KEY, DEPLOYMENT, 86_400, now=NOW)


if __name__ == "__main__":
    unittest.main()
