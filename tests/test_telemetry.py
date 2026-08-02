from __future__ import annotations

import io
import unittest
from contextlib import redirect_stdout
from unittest import mock

from judikt.telemetry import Telemetry


class TelemetryTest(unittest.TestCase):
    def test_disabled_telemetry_is_a_noop(self) -> None:
        telemetry = Telemetry(mode="disabled")

        with telemetry.span("demo", "CHAIN") as span:
            span.set_json_input({"api_key": "[REDACTED]"})
            span.set_json_output({"allowed": True})
            span.set_policy(allowed=True, rule="allow", reason="allowed by policy")

        self.assertEqual(telemetry.status(), {"enabled": False, "mode": "disabled"})

    def test_invalid_mode_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "disabled, console, or otlp"):
            Telemetry(mode="unknown")

    def test_console_span_emits_openinference_attributes(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            telemetry = Telemetry(mode="console")
            with telemetry.span(
                "judikt.qualification", "CHAIN", {"judikt.tool": "platform.health"}
            ) as span:
                span.set_json_input({"api_key": "[REDACTED]"})
                span.set_json_output({"allowed": True})
                span.set_policy(allowed=True, rule="allow", reason="allowed by policy")

        rendered = output.getvalue()
        self.assertIn('"name": "judikt.qualification"', rendered)
        self.assertIn('"openinference.span.kind": "CHAIN"', rendered)
        self.assertIn('"judikt.policy.allowed": true', rendered)
        self.assertIn("[REDACTED]", rendered)
        self.assertEqual(telemetry.status(), {"enabled": True, "mode": "console"})

    def test_exception_trace_records_type_without_private_message(self) -> None:
        from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

        exporter = InMemorySpanExporter()
        with mock.patch(
            "opentelemetry.sdk.trace.export.ConsoleSpanExporter",
            return_value=exporter,
        ), self.assertRaisesRegex(RuntimeError, "private credential"):
            telemetry = Telemetry(mode="console")
            with telemetry.span("judikt.failure", "TOOL"):
                raise RuntimeError("private credential")

        spans = exporter.get_finished_spans()
        self.assertEqual(len(spans), 1)
        self.assertEqual(spans[0].attributes["judikt.error.type"], "RuntimeError")
        self.assertEqual(spans[0].status.status_code.name, "ERROR")
        self.assertNotIn("private credential", str(spans[0].attributes))
        self.assertEqual(spans[0].events, ())


if __name__ == "__main__":
    unittest.main()
