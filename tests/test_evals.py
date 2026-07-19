from __future__ import annotations

import unittest

from mcp_guard.evals import load_mcp38_coverage, run_evals


class EvalHarnessTest(unittest.TestCase):
    def test_adversarial_evals_pass(self) -> None:
        report = run_evals()

        self.assertTrue(report["passed"])
        self.assertEqual(report["passed_count"], report["case_count"])
        self.assertTrue(report["no_secret_leaks"])
        self.assertEqual(report["mcp38"]["total"], 38)

    def test_mcp38_matrix_has_explicit_status_for_all_threats(self) -> None:
        coverage = load_mcp38_coverage()

        self.assertEqual(coverage["total"], 38)
        self.assertEqual(
            coverage["covered"] + coverage["partial"] + coverage["not_covered"],
            38,
        )


if __name__ == "__main__":
    unittest.main()
