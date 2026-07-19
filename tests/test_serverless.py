from __future__ import annotations

import json
import os
import unittest
from unittest import mock

from mcp_guard import serverless


class ServerlessGatewayTests(unittest.TestCase):
    def setUp(self) -> None:
        serverless._POLICY = None
        serverless._CONTENT_GUARD = None

    def test_health_requires_bearer_token_when_configured(self) -> None:
        with mock.patch.dict(os.environ, {"MCP_GUARD_API_TOKEN": "secret"}, clear=False):
            response = serverless.gateway_handler(
                {
                    "rawPath": "/healthz",
                    "requestContext": {"http": {"method": "GET"}},
                    "headers": {"authorization": "Bearer wrong"},
                },
                object(),
            )

        self.assertEqual(response["statusCode"], 401)

    def test_unapproved_rollback_is_blocked_before_tool_lambda(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "MCP_GUARD_API_TOKEN": "secret",
                "MCP_GUARD_APPROVAL_SECRET": "unit-test-secret",
            },
            clear=False,
        ):
            response = serverless.gateway_handler(
                {
                    "rawPath": "/call",
                    "requestContext": {"http": {"method": "POST"}},
                    "headers": {"authorization": "Bearer secret"},
                    "body": json.dumps(
                        {
                            "server": "platform-ops",
                            "tool": "platform.rollback_deployment",
                            "arguments": {
                                "service": "payments-api",
                                "version": "payments-api@2026.05.2",
                                "actor": "gaurav",
                                "rollback_plan": "verify health checks and restore previous release if errors increase",
                            },
                        }
                    ),
                },
                object(),
            )

        payload = json.loads(response["body"])
        self.assertEqual(response["statusCode"], 403)
        self.assertFalse(payload["allowed"])
        self.assertEqual(payload["rule"], "approval_required")

    def test_kubernetes_dry_run_is_allowed_without_tool_lambda_execution(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "MCP_GUARD_API_TOKEN": "secret",
                "MCP_GUARD_APPROVAL_SECRET": "unit-test-secret",
            },
            clear=False,
        ):
            response = serverless.gateway_handler(
                {
                    "rawPath": "/call",
                    "requestContext": {"http": {"method": "POST"}},
                    "headers": {"authorization": "Bearer secret"},
                    "body": json.dumps(
                        {
                            "server": "kubernetes",
                            "tool": "kubernetes.restart_pod",
                            "arguments": {
                                "namespace": "prod",
                                "pod": "payment-service-xyz",
                                "actor": "gaurav",
                                "rollback_plan": "verify health checks and restore previous release if errors increase",
                                "dry_run": True,
                            },
                        }
                    ),
                },
                object(),
            )

        payload = json.loads(response["body"])
        self.assertEqual(response["statusCode"], 200)
        self.assertTrue(payload["allowed"])
        self.assertEqual(payload["action"], "DRY_RUN_ONLY")
        self.assertFalse(payload["result"]["executed"])

    def test_tool_handler_lists_mock_tools(self) -> None:
        result = serverless.tool_handler({"action": "list_tools"}, object())

        self.assertIn("platform-ops", result)
        self.assertIn("incident", result)
        self.assertTrue(any(tool["name"] == "platform.health" for tool in result["platform-ops"]))

    def test_serverless_audit_envelope_is_signed_and_tamper_evident(self) -> None:
        event = {
            "correlation_id": "trace-1",
            "server": "platform-ops",
            "tool": "platform.health",
            "allowed": True,
            "rule": "allow",
        }
        with mock.patch.dict(os.environ, {"MCP_GUARD_AUDIT_HMAC_SECRET": "audit-secret"}):
            sealed = serverless._seal_audit_event(event)

            self.assertTrue(serverless._verify_audit_event(sealed))
            sealed["rule"] = "tampered"
            self.assertFalse(serverless._verify_audit_event(sealed))

    def test_serverless_policy_blocks_caller_supplied_upstream_token(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            policy = serverless.ServerlessPolicy(serverless.POLICY_PATH)
        policy._within_distributed_rate_limit = mock.Mock(return_value=True)

        result = policy.evaluate(
            "platform-ops",
            "platform.health",
            {"service": "payments-api", "access_token": "must-not-pass-through"},
        )

        self.assertFalse(result.allowed)
        self.assertEqual(result.rule, "token_passthrough")


if __name__ == "__main__":
    unittest.main()
