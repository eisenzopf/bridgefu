import json
import os
from pathlib import Path
import stat
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch
import urllib.error
import urllib.request

import client


class ClientTests(unittest.TestCase):
    def setUp(self):
        self.requests = []
        requests = self.requests

        class Backend(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_POST(self):
                requests.append(
                    (
                        self.path,
                        dict(self.headers),
                        json.loads(
                            self.rfile.read(int(self.headers["Content-Length"]))
                        ),
                    )
                )
                if self.path.startswith("/redirect/"):
                    self.send_response(307)
                    self.send_header("Location", "/should-not-receive-token")
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(
                    b'{"attachment":{"type":"webrtc","token":"synthetic-attachment"}}'
                )

        self.backend = ThreadingHTTPServer(("127.0.0.1", 0), Backend)
        self.thread = threading.Thread(target=self.backend.serve_forever)
        self.thread.start()
        self.settings = dict(
            api_url=f"http://127.0.0.1:{self.backend.server_port}",
            route_id="customer-route",
            ingress="webrtc",
            token_env="EXAMPLE_TEST_API_TOKEN",
            context={},
        )
        self.env = patch.dict(
            os.environ, EXAMPLE_TEST_API_TOKEN="synthetic-control-token"
        )
        self.env.start()

    def tearDown(self):
        self.backend.shutdown()
        self.backend.server_close()
        self.thread.join()
        self.env.stop()

    def test_customer_context_and_route_are_forwarded_without_fixed_fields(self):
        self.settings["context"] = {"metadata": {"ticket_number": "synthetic-42"}}
        client.create_call(self.settings)
        path, headers, body = self.requests[0]
        self.assertEqual(path, "/v1/routes/customer-route/calls")
        self.assertEqual(
            body, {"ingress": "webrtc", "context": self.settings["context"]}
        )
        self.assertEqual(headers["Authorization"], "Bearer synthetic-control-token")
        self.assertTrue(headers["Idempotency-Key"])

    def test_empty_context_does_not_add_a_correlation_id(self):
        client.create_call(self.settings)
        self.assertEqual(self.requests[0][2], {"ingress": "webrtc"})

    def test_redirect_does_not_forward_the_control_credential(self):
        self.settings["api_url"] += "/redirect"
        with self.assertRaises(urllib.error.HTTPError):
            client.create_call(self.settings)
        self.assertEqual(len(self.requests), 1)

    def test_private_attachment_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "attachment.json"
            client.save_private(path, {"attachment": "synthetic"})
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            with self.assertRaises(FileExistsError):
                client.save_private(path, {})

    def test_browser_origin_boundary_and_control_token_separation(self):
        server = ThreadingHTTPServer(
            ("127.0.0.1", 0), client.make_handler(self.settings)
        )
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        url = f"http://127.0.0.1:{server.server_port}"
        try:
            with urllib.request.urlopen(url) as response:
                self.assertNotIn(b"synthetic-control-token", response.read())
            bad = urllib.request.Request(
                url + "/call",
                method="POST",
                headers={"Origin": "https://untrusted.example"},
            )
            with self.assertRaises(urllib.error.HTTPError) as error:
                urllib.request.urlopen(bad)
            self.assertEqual(error.exception.code, 403)
            self.assertEqual(self.requests, [])
            good = urllib.request.Request(
                url + "/call", method="POST", headers={"Origin": url}
            )
            with urllib.request.urlopen(good) as response:
                body = response.read()
                self.assertIn(b"synthetic-attachment", body)
                self.assertNotIn(b"synthetic-control-token", body)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


if __name__ == "__main__":
    unittest.main()
