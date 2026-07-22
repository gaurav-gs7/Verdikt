from __future__ import annotations

import importlib
import os
import tomllib
import unittest
from pathlib import Path
from unittest.mock import patch

import verdikt
from verdikt.cli import parser
from verdikt.ops_runtime import GuardedOpsRuntime, VerdiktOpsRuntime
from verdikt.runtime import MCPGuardRuntime, VerdiktRuntime


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class BrandIdentityTest(unittest.TestCase):
    def test_canonical_package_cli_and_distribution_are_verdikt(self) -> None:
        metadata = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text())

        self.assertEqual(metadata["project"]["name"], "verdikt")
        self.assertEqual(metadata["project"]["scripts"]["verdikt"], "verdikt.cli:main")
        self.assertEqual(parser().description, "Verdikt runtime firewall")
        self.assertEqual(parser().get_default("audit_db").name, "verdikt.db")

    def test_legacy_python_import_and_runtime_names_remain_compatible(self) -> None:
        legacy_package = importlib.import_module("mcp_guard")
        legacy_cli = importlib.import_module("mcp_guard.cli")

        self.assertEqual(legacy_package.__version__, verdikt.__version__)
        self.assertEqual(legacy_cli.parser().description, "Verdikt runtime firewall")
        self.assertIs(MCPGuardRuntime, VerdiktRuntime)
        self.assertIs(GuardedOpsRuntime, VerdiktOpsRuntime)

    def test_legacy_environment_is_promoted(self) -> None:
        with patch.dict(
            os.environ,
            {"MCP_GUARD_API_TOKEN": "legacy-token"},
            clear=True,
        ):
            verdikt.promote_legacy_environment()
            self.assertEqual(os.environ["VERDIKT_API_TOKEN"], "legacy-token")

    def test_canonical_environment_takes_precedence(self) -> None:
        with patch.dict(
            os.environ,
            {
                "MCP_GUARD_API_TOKEN": "legacy-token",
                "VERDIKT_API_TOKEN": "verdikt-token",
            },
            clear=True,
        ):
            verdikt.promote_legacy_environment()
            self.assertEqual(os.environ["VERDIKT_API_TOKEN"], "verdikt-token")

    def test_deployment_artifacts_use_canonical_names(self) -> None:
        self.assertTrue((PROJECT_ROOT / "charts" / "verdikt" / "Chart.yaml").is_file())
        self.assertTrue(
            (
                PROJECT_ROOT
                / "infra"
                / "aws"
                / "cloudformation"
                / "verdikt-ec2.yml"
            ).is_file()
        )
        self.assertTrue(
            (
                PROJECT_ROOT
                / "deploy"
                / "observability"
                / "grafana"
                / "dashboards"
                / "verdikt.json"
            ).is_file()
        )

        self.assertFalse((PROJECT_ROOT / "charts" / "mcp-guard").exists())
        self.assertFalse(
            (
                PROJECT_ROOT
                / "infra"
                / "aws"
                / "cloudformation"
                / "mcp-guard-ec2.yml"
            ).exists()
        )


if __name__ == "__main__":
    unittest.main()
