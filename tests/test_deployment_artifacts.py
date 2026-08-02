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
            "JUDIKT_API_TOKEN": "",
            "JUDIKT_APPROVAL_SECRET": "",
            "JUDIKT_AUDIT_HMAC_SECRET": "",
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
            "JUDIKT_API_TOKEN": "api-token",
            "JUDIKT_APPROVAL_SECRET": "same-key",
            "JUDIKT_AUDIT_HMAC_SECRET": "same-key",
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

    def test_cloudformation_deploy_requires_independent_secrets(self) -> None:
        script = PROJECT_ROOT / "scripts" / "aws" / "deploy_ec2.sh"
        missing = subprocess.run(
            [str(script), "example.invalid/judikt:test"],
            cwd=PROJECT_ROOT,
            env={
                **os.environ,
                "JUDIKT_HTTP_BEARER_TOKEN": "",
                "JUDIKT_APPROVAL_SECRET": "",
                "JUDIKT_AUDIT_HMAC_SECRET": "",
            },
            capture_output=True,
            text=True,
            check=False,
        )
        reused = subprocess.run(
            [str(script), "example.invalid/judikt:test"],
            cwd=PROJECT_ROOT,
            env={
                **os.environ,
                "JUDIKT_HTTP_BEARER_TOKEN": "a" * 20,
                "JUDIKT_APPROVAL_SECRET": "same-signing-secret",
                "JUDIKT_AUDIT_HMAC_SECRET": "same-signing-secret",
            },
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(missing.returncode, 2)
        self.assertIn("are required", missing.stderr)
        self.assertEqual(reused.returncode, 2)
        self.assertIn("must be independent", reused.stderr)

        template = (
            PROJECT_ROOT / "infra" / "aws" / "cloudformation" / "judikt-ec2.yml"
        ).read_text()
        self.assertIn("AuditHmacSecretValue", template)
        self.assertIn("JUDIKT_AUDIT_HMAC_SECRET", template)
        self.assertNotIn("set -euxo pipefail", template)
        self.assertIn("Default: 127.0.0.1/32", template)

        terraform_variables = (
            PROJECT_ROOT / "infra" / "aws" / "terraform" / "variables.tf"
        ).read_text()
        self.assertIn('default     = "127.0.0.1/32"', terraform_variables)
        for name in ("deploy_ec2.sh", "deploy_terraform.sh", "destroy_terraform.sh"):
            aws_script = (PROJECT_ROOT / "scripts" / "aws" / name).read_text()
            self.assertIn("JUDIKT_ALLOWED_CIDR:-127.0.0.1/32", aws_script)

        deploy_workflow = (
            PROJECT_ROOT / ".github" / "workflows" / "aws-deploy.yml"
        ).read_text()
        self.assertIn("default: 127.0.0.1/32", deploy_workflow)

        ci_workflow = (PROJECT_ROOT / ".github" / "workflows" / "ci.yml").read_text()
        self.assertIn("mcp,observability,auth,redis,aws,test,quality", ci_workflow)
        self.assertIn("pip-audit", ci_workflow)
        self.assertIn("cfn-lint", ci_workflow)
        self.assertIn("./scripts/run_release_tests.sh", ci_workflow)
        self.assertNotIn("run_tier3_tests.sh", ci_workflow)

        release_script = (PROJECT_ROOT / "scripts" / "run_release_tests.sh").read_text()
        self.assertIn("unittest discover -s tests -v", release_script)
        self.assertIn("--fail-under=85", release_script)
        self.assertIn("--fail-under=100", release_script)
        self.assertIn("run_attackbench.sh", release_script)
        self.assertIn("run_performance_benchmark.sh", release_script)
        self.assertIn("run_community_interop.sh", release_script)

    def test_serverless_terraform_wires_independent_audit_secret(self) -> None:
        terraform = (PROJECT_ROOT / "infra" / "aws" / "serverless" / "main.tf").read_text()
        self.assertIn('resource "aws_secretsmanager_secret" "audit_hmac_secret"', terraform)
        self.assertIn("JUDIKT_AUDIT_HMAC_SECRET_ARN", terraform)
        self.assertIn("JUDIKT_AUDIT_SIGNATURE_REQUIRED", terraform)
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
        self.assertIn("judikt-data:/app/data", compose)
        self.assertIn("judikt-init:", compose)
        self.assertIn("chown -R 10001:10001 /app/data", compose)
        self.assertIn("service_completed_successfully", compose)

        deployment = (
            PROJECT_ROOT / "charts" / "judikt" / "templates" / "deployment.yaml"
        ).read_text()
        pvc = (
            PROJECT_ROOT / "charts" / "judikt" / "templates" / "pvc.yaml"
        ).read_text()
        self.assertIn("mountPath: /app/data", deployment)
        self.assertIn("persistentVolumeClaim", deployment)
        self.assertIn("JUDIKT_AUDIT_SINK", deployment)
        self.assertIn("JUDIKT_SIEM_URL", deployment)
        self.assertIn("JUDIKT_SIEM_TOKEN", deployment)
        self.assertIn("kind: PersistentVolumeClaim", pvc)

    def test_container_and_kubernetes_run_as_non_root(self) -> None:
        dockerfile = (PROJECT_ROOT / "Dockerfile").read_text()
        deployment = (
            PROJECT_ROOT / "charts" / "judikt" / "templates" / "deployment.yaml"
        ).read_text()
        terraform = (PROJECT_ROOT / "infra" / "aws" / "terraform" / "main.tf").read_text()
        cloudformation = (
            PROJECT_ROOT / "infra" / "aws" / "cloudformation" / "judikt-ec2.yml"
        ).read_text()

        self.assertIn("USER 10001:10001", dockerfile)
        self.assertIn("HEALTHCHECK", dockerfile)
        self.assertNotIn("pip install --no-cache-dir -e", dockerfile)
        self.assertIn("automountServiceAccountToken: false", deployment)
        self.assertIn(".Values.securityContext", deployment)
        self.assertIn(".Values.podSecurityContext", deployment)
        self.assertIn("JUDIKT_RESOURCE_URI", deployment)
        self.assertIn("JUDIKT_AUTHORIZATION_SERVER", deployment)
        self.assertIn("JUDIKT_REQUIRED_SCOPES", deployment)
        self.assertIn("install -d -o 10001 -g 10001 /opt/judikt/data", terraform)
        self.assertIn("install -d -o 10001 -g 10001 /opt/judikt/data", cloudformation)

        values = (PROJECT_ROOT / "charts" / "judikt" / "values.yaml").read_text()
        secret = (PROJECT_ROOT / "charts" / "judikt" / "templates" / "secret.yaml").read_text()
        self.assertNotIn('approvalSecret: "change-me"', values)
        self.assertIn('required "approvalSecret is required"', secret)
        self.assertIn("static bearer and JWT authentication cannot be enabled together", secret)


if __name__ == "__main__":
    unittest.main()
