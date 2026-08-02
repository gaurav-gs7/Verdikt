from __future__ import annotations

import importlib
import os
import tomllib
import unittest
from pathlib import Path
from unittest.mock import patch

import judikt
from judikt.cli import parser
from judikt.ops_runtime import GuardedOpsRuntime, JudiktOpsRuntime
from judikt.runtime import MCPGuardRuntime, JudiktRuntime


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class BrandIdentityTest(unittest.TestCase):
    def test_canonical_package_cli_and_distribution_are_judikt(self) -> None:
        metadata = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text())

        self.assertEqual(metadata["project"]["name"], "judikt")
        self.assertEqual(metadata["project"]["scripts"]["judikt"], "judikt.cli:main")
        self.assertEqual(parser().description, "Judikt runtime firewall")
        self.assertEqual(parser().get_default("audit_db").name, "judikt.db")

    def test_legacy_mcp_guard_import_and_runtime_names_remain_compatible(self) -> None:
        legacy_package = importlib.import_module("mcp_guard")
        legacy_cli = importlib.import_module("mcp_guard.cli")

        self.assertEqual(legacy_package.__version__, judikt.__version__)
        self.assertEqual(legacy_cli.parser().description, "Judikt runtime firewall")
        self.assertIs(MCPGuardRuntime, JudiktRuntime)
        self.assertIs(GuardedOpsRuntime, JudiktOpsRuntime)

    def test_legacy_environment_is_promoted(self) -> None:
        with patch.dict(
            os.environ,
            {"MCP_GUARD_API_TOKEN": "legacy-token"},
            clear=True,
        ):
            judikt.promote_legacy_environment()
            self.assertEqual(os.environ["JUDIKT_API_TOKEN"], "legacy-token")

    def test_canonical_environment_takes_precedence(self) -> None:
        with patch.dict(
            os.environ,
            {
                "MCP_GUARD_API_TOKEN": "legacy-token",
                "JUDIKT_API_TOKEN": "judikt-token",
            },
            clear=True,
        ):
            judikt.promote_legacy_environment()
            self.assertEqual(os.environ["JUDIKT_API_TOKEN"], "judikt-token")

    def test_deployment_artifacts_use_canonical_names(self) -> None:
        self.assertTrue((PROJECT_ROOT / "charts" / "judikt" / "Chart.yaml").is_file())
        self.assertTrue(
            (
                PROJECT_ROOT
                / "infra"
                / "aws"
                / "cloudformation"
                / "judikt-ec2.yml"
            ).is_file()
        )
        self.assertTrue(
            (
                PROJECT_ROOT
                / "deploy"
                / "observability"
                / "grafana"
                / "dashboards"
                / "judikt.json"
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
