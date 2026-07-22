from __future__ import annotations

import hashlib
import hmac
import json
import os
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from verdikt.findings import FindingDispatcher, build_finding_event


class ArgusHTTPIntegrationTest(unittest.TestCase):
    def test_real_http_delivery_retries_503_and_preserves_private_data_boundary(self) -> None:
        requests: list[dict[str, object]] = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802 - stdlib callback name
                body = self.rfile.read(int(self.headers["content-length"]))
                requests.append(
                    {
                        "path": self.path,
                        "headers": {key.lower(): value for key, value in self.headers.items()},
                        "body": body,
                    }
                )
                self.send_response(503 if len(requests) == 1 else 202)
                self.end_headers()

            def log_message(self, format: str, *args: object) -> None:
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as directory, patch.dict(
                os.environ,
                {
                    "VERDIKT_ARGUS_URL": f"http://127.0.0.1:{server.server_port}",
                    "VERDIKT_ARGUS_API_TOKEN": "operator-token",
                    "VERDIKT_ARGUS_HMAC_SECRET": "event-signing-secret",
                    "VERDIKT_FINDING_RETRY_INTERVAL_SECONDS": "0.1",
                    "VERDIKT_FINDING_RETRY_BASE_SECONDS": "0.01",
                },
                clear=False,
            ):
                dispatcher = FindingDispatcher(Path(directory) / "findings.db")
                event = build_finding_event(
                    correlation_id="corr\nprivate",
                    server="platform-ops",
                    tool="platform.run_diagnostic",
                    allowed=False,
                    rule="blocked_pattern",
                    action="DENY",
                    reason="secret reason",
                    risk_score=75,
                    risk_level="high",
                    arguments={"command": "curl https://private.invalid/secret"},
                    result={"token": "raw-result-secret"},
                )
                try:
                    self.assertEqual(dispatcher.dispatch(event), "pending")
                    deadline = time.time() + 2
                    while dispatcher.status()["delivered"] != 1 and time.time() < deadline:
                        time.sleep(0.02)
                    self.assertEqual(dispatcher.status()["delivered"], 1)
                finally:
                    dispatcher.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        self.assertEqual(len(requests), 2)
        delivered = requests[-1]
        self.assertEqual(delivered["path"], "/v1/alerts/alertmanager")
        self.assertEqual(delivered["headers"]["authorization"], "Bearer operator-token")
        expected = "sha256=" + hmac.new(
            b"event-signing-secret", delivered["body"], hashlib.sha256
        ).hexdigest()
        self.assertEqual(delivered["headers"]["x-verdikt-signature-256"], expected)
        rendered = delivered["body"].decode()
        self.assertNotIn("private.invalid", rendered)
        self.assertNotIn("raw-result-secret", rendered)
        self.assertNotIn("secret reason", rendered)
        self.assertEqual(json.loads(rendered)["receiver"], "verdikt")


if __name__ == "__main__":
    unittest.main()
