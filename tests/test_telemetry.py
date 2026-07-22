from __future__ import annotations

import unittest

from verdikt.telemetry import Telemetry


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


if __name__ == "__main__":
    unittest.main()
