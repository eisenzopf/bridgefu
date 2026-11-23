#!/usr/bin/env python3
"""Small local application backend; the Bridgefu API token stays server-side."""

import argparse
import json
import mimetypes
import os
from pathlib import Path
import ssl
import urllib.error
import urllib.parse
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = Path(__file__).resolve().parents[2]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def load_settings(path):
    settings = json.loads(Path(path).read_text())
    allowed = {
        "api_url",
        "route_id",
        "ingress",
        "token_env",
        "context",
        "browser_port",
        "ca_file",
    }
    if set(settings) - allowed:
        raise ValueError("Unknown client setting")
    url = urllib.parse.urlsplit(settings["api_url"])
    if url.username or url.password or url.query or url.fragment:
        raise ValueError("API URL must not contain credentials, query, or fragment")
    if url.scheme != "https" and not (
        url.scheme == "http" and url.hostname in {"localhost", "127.0.0.1", "::1"}
    ):
        raise ValueError("Use HTTPS for a remote Bridgefu API")
    if settings["ingress"] not in {"sip", "webrtc"}:
        raise ValueError("ingress must be sip or webrtc")
    if not settings["route_id"] or not isinstance(settings.get("context", {}), dict):
        raise ValueError("A route ID and an object-valued context are required")
    return settings


def create_call(settings):
    body = {"ingress": settings["ingress"]}
    if settings.get("context"):
        body["context"] = settings["context"]
    token = os.environ[settings["token_env"]]
    url = (
        settings["api_url"].rstrip("/")
        + "/v1/routes/"
        + urllib.parse.quote(settings["route_id"], safe="")
        + "/calls"
    )
    request = urllib.request.Request(
        url,
        data=json.dumps(body).encode(),
        method="POST",
        headers={
            "Authorization": "Bearer " + token,
            "Idempotency-Key": str(uuid.uuid4()),
            "Content-Type": "application/json",
        },
    )
    context = ssl.create_default_context(cafile=settings.get("ca_file"))
    opener = urllib.request.build_opener(
        NoRedirect, urllib.request.HTTPSHandler(context=context)
    )
    with opener.open(request, timeout=30) as response:
        return json.load(response)


def save_private(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Refuse symlinks and existing files so an old attachment is never overwritten.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as out:
        json.dump(value, out, indent=2)
        out.write("\n")


def make_handler(settings):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def reply(self, status, data, content_type="application/json"):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.path == "/":
                path = Path(__file__).with_name("browser.html")
            elif self.path.startswith("/sdk/"):
                root = (ROOT / "sdk/typescript/dist").resolve()
                path = (root / self.path.removeprefix("/sdk/")).resolve()
                if not path.is_relative_to(root):
                    self.reply(404, b"{}")
                    return
            else:
                self.reply(404, b"{}")
                return
            if not path.is_file():
                self.reply(404, b"{}")
                return
            self.reply(
                200,
                path.read_bytes(),
                mimetypes.guess_type(path)[0] or "application/octet-stream",
            )

        def do_POST(self):
            expected = f"http://127.0.0.1:{self.server.server_port}"
            if (
                self.path != "/call"
                or self.headers.get("Origin") != expected
                or self.headers.get("Host") != f"127.0.0.1:{self.server.server_port}"
            ):
                self.reply(403, b'{"error":"origin rejected"}')
                return
            if self.headers.get("Content-Length", "0") != "0":
                self.reply(400, b'{"error":"request body is not accepted"}')
                return
            try:
                self.reply(200, json.dumps(create_call(settings)).encode())
            except (urllib.error.URLError, OSError, ValueError, KeyError):
                self.reply(
                    502,
                    b'{"error":"Call creation failed; check the API URL, token, route, and Bridgefu logs."}',
                )

    return Handler


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--settings", required=True)
    parser.add_argument(
        "--output", help="New private file for a SIP attachment response"
    )
    parser.add_argument(
        "--serve", action="store_true", help="Serve the local browser caller"
    )
    args = parser.parse_args()
    settings = load_settings(args.settings)
    if not os.environ.get(settings["token_env"]):
        parser.error("The configured API-token environment variable is not set")
    if args.serve:
        if settings["ingress"] != "webrtc" or args.output:
            parser.error("--serve requires WebRTC ingress and no --output")
        if not (ROOT / "sdk/typescript/dist/index.js").is_file():
            parser.error(
                "Build the SDK first: npm ci --prefix sdk/typescript && npm run build --prefix sdk/typescript"
            )
        server = ThreadingHTTPServer(
            ("127.0.0.1", settings.get("browser_port", 8080)), make_handler(settings)
        )
        print(
            f"Open http://127.0.0.1:{server.server_port}/ and press Call. Ctrl-C stops this local app.",
            flush=True,
        )
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
    else:
        if not args.output:
            parser.error(
                "--output is required; attachments are not printed to the terminal"
            )
        if Path(args.output).exists() or Path(args.output).is_symlink():
            parser.error(
                "Output already exists; delete the expired attachment or choose a new path"
            )
        save_private(args.output, create_call(settings))
        print(
            "Saved a private, short-lived call attachment. Use it once, then delete the file."
        )


if __name__ == "__main__":
    main()
