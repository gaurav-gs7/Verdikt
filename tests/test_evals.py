from __future__ import annotations

import unittest

from mcp_guard.evals import run_evals


class EvalHarnessTest(unittest.TestCase):
    def test_adversarial_evals_pass(self) -> None:
        report = run_evals()

        self.assertTrue(report["passed"])
        self.assertEqual(report["passed_count"], report["case_count"])
        self.assertTrue(report["no_secret_leaks"])


if __name__ == "__main__":
    unittest.main()
