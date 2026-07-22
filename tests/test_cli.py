from __future__ import annotations

import unittest
from pathlib import Path

from verdikt.cli import parser


class CLITest(unittest.TestCase):
    def test_runtime_options_are_accepted_after_public_subcommand(self) -> None:
        args = parser().parse_args(["serve-mcp", "--audit-db", "/tmp/verdikt-test.db"])

        self.assertEqual(args.command, "serve-mcp")
        self.assertEqual(args.audit_db, Path("/tmp/verdikt-test.db"))

    def test_runtime_options_are_still_accepted_before_public_subcommand(self) -> None:
        args = parser().parse_args(["--audit-db", "/tmp/verdikt-test.db", "serve-mcp"])

        self.assertEqual(args.command, "serve-mcp")
        self.assertEqual(args.audit_db, Path("/tmp/verdikt-test.db"))

    def test_attackbench_threshold_options_are_parsed(self) -> None:
        args = parser().parse_args(
            [
                "attackbench",
                "tests/fixtures/attackbench_smoke.jsonl",
                "--expected-samples",
                "8",
                "--min-recall",
                "0.9",
            ]
        )

        self.assertEqual(args.command, "attackbench")
        self.assertEqual(args.expected_samples, 8)
        self.assertEqual(args.min_recall, 0.9)


if __name__ == "__main__":
    unittest.main()
