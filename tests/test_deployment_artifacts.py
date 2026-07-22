from __future__ import annotations

import os
import subprocess
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class DeploymentArtifactTest(unittest.TestCase):
    def test_serverless_deploy_fails_before_aws_when_secrets_are_missing(self) -> None:
        env = {
            **os.environ,
            "VERDIKT_API_TOKEN": "",
            "VERDIKT_APPROVAL_SECRET": "",
            "VERDIKT_AUDIT_HMAC_SECRET": "",
        }
        result = subprocess.run(
            [str(PROJECT_ROOT / "scripts" / "aws" / "deploy_serverless.sh")],
            cwd=PROJECT_ROOT,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("are required", result.stderr)

    def test_serverless_deploy_rejects_key_reuse(self) -> None:
        env = {
            **os.environ,
            "VERDIKT_API_TOKEN": "api-token",
            "VERDIKT_APPROVAL_SECRET": "same-key",
            "VERDIKT_AUDIT_HMAC_SECRET": "same-key",
        }
        result = subprocess.run(
            [str(PROJECT_ROOT / "scripts" / "aws" / "deploy_serverless.sh")],
            cwd=PROJECT_ROOT,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("must be independent", result.stderr)

    def test_serverless_terraform_wires_independent_audit_secret(self) -> None:
        terraform = (PROJECT_ROOT / "infra" / "aws" / "serverless" / "main.tf").read_text()
        self.assertIn('resource "aws_secretsmanager_secret" "audit_hmac_secret"', terraform)
        self.assertIn("VERDIKT_AUDIT_HMAC_SECRET_ARN", terraform)
        self.assertIn("VERDIKT_AUDIT_SIGNATURE_REQUIRED", terraform)
        self.assertIn("aws_secretsmanager_secret.audit_hmac_secret.arn", terraform)
        self.assertNotIn('secret_string = var.', terraform)
        destroy_script = (
            PROJECT_ROOT / "scripts" / "aws" / "destroy_serverless.sh"
        ).read_text()
        self.assertNotIn("api_token=", destroy_script)
        self.assertNotIn("approval_secret=", destroy_script)

    def test_deployment_templates_persist_outbox_and_redis_state(self) -> None:
        compose = (
            PROJECT_ROOT / "deploy" / "observability" / "docker-compose.yml"
        ).read_text()
        self.assertIn("--appendonly", compose)
        self.assertIn("redis-data:/data", compose)
        self.assertIn("verdikt-data:/app/data", compose)

        deployment = (
            PROJECT_ROOT / "charts" / "verdikt" / "templates" / "deployment.yaml"
        ).read_text()
        pvc = (
            PROJECT_ROOT / "charts" / "verdikt" / "templates" / "pvc.yaml"
        ).read_text()
        self.assertIn("mountPath: /app/data", deployment)
        self.assertIn("persistentVolumeClaim", deployment)
        self.assertIn("kind: PersistentVolumeClaim", pvc)


if __name__ == "__main__":
    unittest.main()
