from __future__ import annotations

import contextlib
import io
import json
import sys
import time
import unittest
from pathlib import Path


COMMON = Path(__file__).resolve().parents[2] / "lambda" / "common"
sys.path.insert(0, str(COMMON))

import aws_runtime  # noqa: E402
from bridgefu_handoff import HandoffError  # noqa: E402


class FakeSecrets:
    def __init__(self):
        self.calls = 0

    def get_secret_value(self, **_kwargs):
        self.calls += 1
        return {"SecretString": f"secret-{self.calls}-" + "x" * 32}


class ConditionalFailure(Exception):
    def __init__(self):
        self.response = {"Error": {"Code": "ConditionalCheckFailedException"}}


class FakeDynamo:
    def __init__(self):
        self.item = None
        self.last_get = None
        self.updates = []

    def get_item(self, **kwargs):
        self.last_get = kwargs
        return {"Item": self.item} if self.item is not None else {}

    def put_item(self, **kwargs):
        if self.item is not None:
            raise ConditionalFailure()
        self.item = kwargs["Item"]

    def update_item(self, **kwargs):
        self.updates.append(kwargs)


class AwsRuntimeTests(unittest.TestCase):
    def setUp(self):
        aws_runtime._SECRET_CACHE.clear()

    def test_secret_cache_is_bounded_and_refreshes_for_rotation(self):
        client = FakeSecrets()
        arn = "arn:aws:secretsmanager:us-west-2:123456789012:secret:test"
        first = aws_runtime.load_secret(arn, client=client, now=0)
        self.assertEqual(first, aws_runtime.load_secret(arn, client=client, now=299))
        self.assertEqual(client.calls, 1)
        rotated = aws_runtime.load_secret(arn, client=client, now=301)
        self.assertNotEqual(first, rotated)
        self.assertEqual(client.calls, 2)

    def test_dynamo_adapter_is_consistent_bounded_and_idempotent(self):
        client = FakeDynamo()
        store = aws_runtime.DynamoHandoffStore("handoff-table", client=client)
        record = {
            "schema_version": 1,
            "correlation_id": "bf1_" + "a" * 43,
            "vapi_call_fingerprint": "b" * 64,
            "content_hash": "c" * 64,
            "handoff_status": "PREPARED",
            "expires_at": 1_900_000_000,
        }
        self.assertEqual(store.put_prepared(record), "created")
        self.assertEqual(store.put_prepared(record), "replayed")
        loaded = store.get(record["correlation_id"])
        self.assertEqual(loaded, record)
        self.assertTrue(client.last_get["ConsistentRead"])
        projection = client.last_get["ProjectionExpression"]
        self.assertNotIn("transcript", projection)
        self.assertNotIn("recording", projection)

        conflict = {**record, "content_hash": "d" * 64}
        with self.assertRaisesRegex(HandoffError, "handoff_replay_conflict"):
            store.put_prepared(conflict)

    def test_route_client_requires_https_origin_and_no_embedded_path(self):
        token = "t" * 32
        for url in (
            "http://control.example.com",
            "https://user@control.example.com",
            "https://control.example.com/private",
            "https://control.example.com?token=bad",
        ):
            with self.subTest(url=url):
                with self.assertRaisesRegex(HandoffError, "bridgefu_configuration_invalid"):
                    aws_runtime.BridgefuRouteClient(url, "support", token)
        client = aws_runtime.BridgefuRouteClient(
            "https://control.example.com", "support", token
        )
        redirect_handler = next(
            handler
            for handler in client._opener.handlers
            if isinstance(handler, aws_runtime._NoRedirect)
        )
        self.assertIsNone(
            redirect_handler.redirect_request(None, None, 302, "", {}, "https://evil.invalid")
        )

        private_host = "control.bft-test1234.bridgefu.internal"
        private = aws_runtime.BridgefuRouteClient(
            f"http://{private_host}:443",
            "support",
            token,
            private_http_hostname=private_host,
        )
        self.assertTrue(
            any(
                isinstance(handler, aws_runtime.urllib.request.HTTPHandler)
                for handler in private._opener.handlers
            )
        )
        for url, expected_host in (
            (f"http://{private_host}", private_host),
            (f"http://{private_host}:80", private_host),
            ("http://control.bft-other.bridgefu.internal:443", private_host),
            ("http://control.example.com:443", "control.example.com"),
        ):
            with self.subTest(url=url):
                with self.assertRaisesRegex(
                    HandoffError, "bridgefu_configuration_invalid"
                ):
                    aws_runtime.BridgefuRouteClient(
                        url,
                        "support",
                        token,
                        private_http_hostname=expected_host,
                    )

    def test_emf_log_contains_only_bounded_operational_fields(self):
        output = io.StringIO()
        sensitive = "bf1_" + "z" * 43
        with contextlib.redirect_stdout(output):
            aws_runtime.emit_operation(sensitive, "bad\nresult", time.monotonic())
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["event"], "internal")
        self.assertEqual(payload["result"], "internal_error")
        self.assertNotIn(sensitive, output.getvalue())
        self.assertEqual(payload["Requests"], 1)
        self.assertGreaterEqual(payload["Duration"], 0)
        self.assertEqual(
            payload["_aws"]["CloudWatchMetrics"][0]["Namespace"],
            "Bridgefu/Recipe",
        )

    def test_correlation_audit_log_is_redacted_and_bounded(self):
        correlation = "bf1_" + "z" * 43
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            aws_runtime.emit_correlation_evidence(
                "connect_lookup",
                "available",
                correlation,
            )
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["event"], "bridgefu_correlation_evidence")
        self.assertEqual(payload["operation"], "connect_lookup")
        self.assertEqual(payload["result"], "available")
        self.assertRegex(payload["correlation_fingerprint"], r"^[0-9a-f]{12}$")
        self.assertNotIn(correlation, output.getvalue())

        rejected = io.StringIO()
        with contextlib.redirect_stdout(rejected):
            aws_runtime.emit_correlation_evidence(
                "bad\noperation",
                "available",
                correlation,
            )
            aws_runtime.emit_correlation_evidence(
                "connect_lookup",
                "available",
                "not-a-correlation",
            )
        self.assertEqual(rejected.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
