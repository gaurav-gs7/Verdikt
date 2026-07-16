from __future__ import annotations

import json
import threading
import unittest
import urllib.error
import urllib.request

from mcp_guard.http_app import DashboardServer


class _Audit:
    def recent(self) -> list[dict[str, object]]:
        return []


class _Runtime:
    audit = _Audit()


class DashboardAuthenticationTest(unittest.TestCase):
    def test_non_loopback_binding_requires_token(self) -> None:
        with self.assertRaisesRegex(ValueError, "MCP_GUARD_API_TOKEN"):
            DashboardServer(("0.0.0.0", 0), _Runtime())  # type: ignore[arg-type]

    def test_health_is_public_but_api_requires_bearer_token(self) -> None:
        server = DashboardServer(
            ("127.0.0.1", 0),
            _Runtime(),  # type: ignore[arg-type]
            api_token="integration-secret",
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base_url = f"http://127.0.0.1:{server.server_port}"
        try:
            with urllib.request.urlopen(f"{base_url}/healthz", timeout=3) as response:
                self.assertEqual(json.load(response), {"status": "ok"})

            with self.assertRaises(urllib.error.HTTPError) as unauthorized:
                urllib.request.urlopen(f"{base_url}/api/events", timeout=3)
            self.assertEqual(unauthorized.exception.code, 401)
            self.assertEqual(
                unauthorized.exception.headers["WWW-Authenticate"],
                "Bearer",
            )
            unauthorized.exception.close()

            request = urllib.request.Request(
                f"{base_url}/api/events",
                headers={"Authorization": "Bearer integration-secret"},
            )
            with urllib.request.urlopen(request, timeout=3) as response:
                self.assertEqual(json.load(response), [])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)


if __name__ == "__main__":
    unittest.main()
