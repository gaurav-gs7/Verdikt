from __future__ import annotations

import io
import json
import os
import unittest
import urllib.error
from unittest import mock

from verdikt.groq import IncidentAnalyst, MAX_REQUEST_BYTES
from verdikt.telemetry import Telemetry


class Response(io.BytesIO):
    def __enter__(self) -> "Response":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


class GroqIncidentAnalystTest(unittest.TestCase):
    def analyst(self, api_key: str | None = "test-api-key") -> IncidentAnalyst:
        return IncidentAnalyst(api_key=api_key, telemetry=Telemetry("disabled"))

    def test_local_fallback_handles_incomplete_events(self) -> None:
        result = self.analyst("").summarize(
            [{"allowed": False, "rule": "blocked_pattern"}, {}, {"allowed": True}]
        )

        self.assertEqual(result["provider"], "local-fallback")
        self.assertIn("3 MCP tool calls", result["summary"])
        self.assertIn("blocked_pattern", result["summary"])

    def test_success_redacts_and_bounds_provider_request(self) -> None:
        body = json.dumps(
            {"choices": [{"message": {"content": "- Impact: one blocked call"}}]}
        ).encode()
        events = [
            {
                "allowed": False,
                "rule": "blocked_pattern",
                "api_key": "sk-private-value",
                "message": "Bearer private-provider-token",
                "large": "x" * 20_000,
            }
            for _ in range(30)
        ]
        captured: dict[str, object] = {}

        def open_request(request: object, timeout: int) -> Response:
            captured["request"] = request
            captured["timeout"] = timeout
            return Response(body)

        with mock.patch("urllib.request.urlopen", side_effect=open_request):
            result = self.analyst().summarize(events)

        self.assertEqual(result["provider"], "groq")
        request = captured["request"]
        payload = json.loads(request.data)
        user_events = json.loads(payload["messages"][1]["content"])
        rendered = json.dumps(user_events)
        self.assertLessEqual(len(rendered.encode()), MAX_REQUEST_BYTES)
        self.assertNotIn("sk-private-value", rendered)
        self.assertNotIn("private-provider-token", rendered)
        self.assertIn("[REDACTED]", rendered)
        self.assertEqual(captured["timeout"], 15)
        self.assertEqual(request.get_header("Authorization"), "Bearer test-api-key")

    def test_provider_failures_are_generic_and_fall_back(self) -> None:
        cases: list[object] = [
            urllib.error.URLError("private network detail"),
            Response(b"not-json"),
            Response(b"{}"),
            Response(b"x" * 1_048_577),
            Response(json.dumps({"choices": [{"message": {"content": ""}}]}).encode()),
        ]
        for outcome in cases:
            with self.subTest(outcome=type(outcome).__name__), mock.patch(
                "urllib.request.urlopen",
                side_effect=outcome if isinstance(outcome, Exception) else None,
                return_value=None if isinstance(outcome, Exception) else outcome,
            ):
                result = self.analyst().summarize(
                    [{"allowed": False, "rule": "blocked_pattern"}]
                )
                self.assertEqual(result["provider"], "local-fallback")
                self.assertEqual(
                    result["warning"], "Groq request failed; local fallback used"
                )
                self.assertNotIn("private network detail", json.dumps(result))

    def test_api_key_can_be_resolved_by_secret_broker(self) -> None:
        with mock.patch.dict(
            os.environ, {"GROQ_API_KEY_SECRET_ARN": "groq-secret"}, clear=True
        ), mock.patch(
            "verdikt.groq.resolve_configured_secret", return_value="brokered-key"
        ) as resolve:
            analyst = IncidentAnalyst(telemetry=Telemetry("disabled"))

        self.assertEqual(analyst.api_key, "brokered-key")
        resolve.assert_called_once()


if __name__ == "__main__":
    unittest.main()
