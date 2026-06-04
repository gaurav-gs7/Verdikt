from __future__ import annotations

import unittest
from pathlib import Path

from mcp_guard.cli import parser


class CLITest(unittest.TestCase):
    def test_runtime_options_are_accepted_after_public_subcommand(self) -> None:
        args = parser().parse_args(["serve-mcp", "--audit-db", "/tmp/mcp-guard-test.db"])

        self.assertEqual(args.command, "serve-mcp")
        self.assertEqual(args.audit_db, Path("/tmp/mcp-guard-test.db"))

    def test_runtime_options_are_still_accepted_before_public_subcommand(self) -> None:
        args = parser().parse_args(["--audit-db", "/tmp/mcp-guard-test.db", "serve-mcp"])

        self.assertEqual(args.command, "serve-mcp")
        self.assertEqual(args.audit_db, Path("/tmp/mcp-guard-test.db"))


if __name__ == "__main__":
    unittest.main()
