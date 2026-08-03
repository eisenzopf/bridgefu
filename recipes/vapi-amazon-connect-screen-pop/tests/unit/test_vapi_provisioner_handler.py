from __future__ import annotations

import importlib.util
import sys
import unittest
import urllib.error
from pathlib import Path
from unittest import mock


RECIPE = Path(__file__).resolve().parents[2]
COMMON = RECIPE / "lambda" / "common"
HANDLER_PATH = RECIPE / "lambda" / "vapi_provisioner" / "handler.py"
sys.path.insert(0, str(COMMON))

SPEC = importlib.util.spec_from_file_location(
    "bridgefu_vapi_provisioner_handler", HANDLER_PATH
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("unable to load Vapi provisioner handler")
HANDLER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HANDLER)


class VapiProvisionerHandlerTests(unittest.TestCase):
    def test_vapi_budget_reserves_the_cloudformation_response_window(self):
        context = mock.Mock()
        context.get_remaining_time_in_millis.side_effect = [20_000, 15_999]

        self.assertEqual(HANDLER._vapi_request_timeout(context), 5.0)
        with self.assertRaisesRegex(
            HANDLER.VapiProvisioningError, "vapi_operation_budget_exhausted"
        ):
            HANDLER._vapi_request_timeout(context)

    def test_cloudformation_response_put_has_two_bounded_attempts(self):
        event = {
            "StackId": "stack-id",
            "RequestId": "request-id",
            "LogicalResourceId": "VapiResources",
            "ResponseURL": "https://cloudformation-response.example.test/result",
        }
        context = mock.Mock()
        context.get_remaining_time_in_millis.side_effect = [15_000, 8_000]
        response = mock.MagicMock()
        response.__enter__.return_value = response

        with mock.patch.object(
            HANDLER.urllib.request,
            "urlopen",
            side_effect=[urllib.error.URLError("transient"), response],
        ) as urlopen:
            HANDLER._send(
                event,
                "FAILED",
                "bridgefu-vapi-pending",
                {},
                "bounded_failure",
                context=context,
            )

        self.assertEqual(urlopen.call_count, 2)
        self.assertEqual(
            [call.kwargs["timeout"] for call in urlopen.call_args_list],
            [6.0, 6.0],
        )

    def test_failed_create_delete_does_not_require_webhook_secret(self):
        event = {
            "RequestType": "Delete",
            "PhysicalResourceId": "bridgefu-vapi-pending",
            "StackId": (
                "arn:aws:cloudformation:us-east-1:123456789012:"
                "stack/bridgefu-test/stack-id"
            ),
            "RequestId": "request-id",
            "LogicalResourceId": "VapiResources",
            "ResponseURL": "https://cloudformation-response.example.test/result",
            "ResourceProperties": {
                "DeploymentId": "bf-test-001",
                "VapiApiKeySecretArn": (
                    "arn:aws:secretsmanager:us-east-1:123456789012:secret:vapi"
                ),
                "WebhookSecretArn": (
                    "arn:aws:secretsmanager:us-east-1:123456789012:secret:webhook"
                ),
                "PrepareUrl": "https://example.test/prepare",
                "TransferUrl": "https://example.test/transfer",
                "Model": "gpt-4.1-mini",
                "VoiceId": "Elliot",
                "RetainVapiResourcesOnDelete": "false",
            },
        }
        secret_reads = []
        delete_calls = []
        responses = []

        def load_secret(arn):
            secret_reads.append(arn)
            return "vapi-private-key-" + "x" * 32

        def delete(_client, config, physical_id):
            delete_calls.append((config, physical_id))

        def send(_event, status, physical_id, data, reason, *, context=None):
            responses.append((status, physical_id, data, reason))

        with (
            mock.patch.dict(
                HANDLER.os.environ,
                {"VAPI_ASSET_ROOT": str(RECIPE / "vapi")},
            ),
            mock.patch.object(HANDLER, "load_secret", side_effect=load_secret),
            mock.patch.object(
                HANDLER, "VapiHttpClient", return_value=object()
            ) as client_constructor,
            mock.patch.object(HANDLER, "provision_delete", side_effect=delete),
            mock.patch.object(HANDLER, "_send", side_effect=send),
            mock.patch.object(HANDLER, "emit_operation"),
        ):
            HANDLER.lambda_handler(event, None)

        self.assertEqual(
            secret_reads,
            [event["ResourceProperties"]["VapiApiKeySecretArn"]],
        )
        self.assertEqual(len(delete_calls), 1)
        self.assertIsNone(delete_calls[0][0].webhook_token)
        self.assertEqual(delete_calls[0][1], "bridgefu-vapi-pending")
        self.assertEqual(
            responses,
            [
                (
                    "SUCCESS",
                    "bridgefu-vapi-pending",
                    {},
                    "recipe-owned resources deleted",
                )
            ],
        )
        request_timeout = client_constructor.call_args.kwargs["request_timeout"]
        self.assertEqual(request_timeout(), HANDLER.VAPI_REQUEST_TIMEOUT_SECONDS)


if __name__ == "__main__":
    unittest.main()
