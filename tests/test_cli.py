from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path

from verdikt.cli import parser


class CLITest(unittest.TestCase):
    def test_remote_server_configuration_error_is_concise(self) -> None:
        project_root = Path(__file__).resolve().parents[1]
        environment = {
            **os.environ,
            "PYTHONPATH": str(project_root / "src"),
            "VERDIKT_HTTP_BEARER_TOKEN": "",
            "VERDIKT_JWT_HS256_SECRET": "",
            "VERDIKT_JWT_JWKS_URL": "",
        }
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "verdikt.cli",
                "serve-real-mcp",
                "--host",
                "0.0.0.0",
                "--port",
                "18080",
            ],
            cwd=project_root,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 1)
        self.assertIn("remote MCP binding requires bearer or JWT authentication", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

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

    def test_performance_threshold_options_are_parsed(self) -> None:
        args = parser().parse_args(
            [
                "performance",
                "--iterations",
                "50",
                "--warmup",
                "5",
                "--max-p99-ms",
                "25",
                "--min-throughput",
                "20",
            ]
        )

        self.assertEqual(args.command, "performance")
        self.assertEqual(args.iterations, 50)
        self.assertEqual(args.warmup, 5)
        self.assertEqual(args.max_p99_ms, 25)
        self.assertEqual(args.min_throughput, 20)


if __name__ == "__main__":
    unittest.main()
