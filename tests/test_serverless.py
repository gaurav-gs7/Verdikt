from __future__ import annotations

import json
import os
import unittest
from unittest import mock

from verdikt import serverless


class ServerlessGatewayTests(unittest.TestCase):
    def setUp(self) -> None:
        serverless._POLICY = None
        serverless._CONTENT_GUARD = None
        serverless._SECRET_CACHE.clear()

    def test_health_requires_bearer_token_when_configured(self) -> None:
        with mock.patch.dict(os.environ, {"VERDIKT_API_TOKEN": "secret"}, clear=False):
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
                "VERDIKT_API_TOKEN": "secret",
                "VERDIKT_APPROVAL_SECRET": "unit-test-secret",
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
                "VERDIKT_API_TOKEN": "secret",
                "VERDIKT_APPROVAL_SECRET": "unit-test-secret",
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
        with mock.patch.dict(os.environ, {"VERDIKT_AUDIT_HMAC_SECRET": "audit-secret"}):
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

    def test_eventbridge_finding_uses_shared_private_safe_contract(self) -> None:
        client = mock.Mock()
        client.put_events.return_value = {"FailedEntryCount": 0, "Entries": [{}]}
        event = {
            "correlation_id": "corr\nprivate-value",
            "server": "platform ops",
            "tool": "platform.run_diagnostic/<unsafe>",
            "allowed": False,
            "rule": "blocked_pattern",
            "action": "DENY",
            "reason": "raw secret reason",
            "arguments": {"command": "curl https://private.invalid/secret"},
            "result": {"token": "raw-result-secret"},
            "risk_score": 75,
            "risk_level": "high",
        }
        with mock.patch.dict(os.environ, {"EVENT_BUS_NAME": "security-bus"}, clear=False), mock.patch(
            "verdikt.serverless._events_client", return_value=client
        ):
            serverless._publish_finding(event)

        entry = client.put_events.call_args.kwargs["Entries"][0]
        detail = json.loads(entry["Detail"])
        self.assertEqual(entry["Source"], "verdikt.mcp")
        self.assertEqual(entry["DetailType"], "RemediationFinding")
        self.assertEqual(entry["EventBusName"], "security-bus")
        self.assertEqual(detail["schema_version"], 1)
        self.assertEqual(detail["event_type"], "verdikt.mcp.security_finding")
        self.assertEqual(len(detail["arguments_hash"]), 64)
        rendered = json.dumps(detail)
        self.assertNotIn("private.invalid", rendered)
        self.assertNotIn("raw-result-secret", rendered)
        self.assertNotIn("raw secret reason", rendered)
        self.assertNotIn("\n", detail["correlation_id"])

    def test_eventbridge_exception_and_rejected_entry_only_emit_failure_metric(self) -> None:
        event = {
            "correlation_id": "corr",
            "server": "platform-ops",
            "tool": "platform.run_diagnostic",
            "allowed": False,
            "rule": "blocked_pattern",
            "action": "DENY",
            "reason": "blocked",
            "arguments": {},
            "result": None,
            "risk_score": 75,
            "risk_level": "high",
        }
        for response, side_effect, failure_class in (
            ({"FailedEntryCount": 1}, None, "RejectedEntry"),
            (None, RuntimeError("eventbridge down"), "RuntimeError"),
        ):
            with self.subTest(failure_class=failure_class), mock.patch.dict(
                os.environ, {"EVENT_BUS_NAME": "security-bus"}, clear=False
            ), mock.patch("verdikt.serverless._events_client") as factory, mock.patch(
                "verdikt.serverless._metric"
            ) as metric, mock.patch("builtins.print") as log:
                factory.return_value.put_events.return_value = response
                factory.return_value.put_events.side_effect = side_effect
                serverless._publish_finding(event)
                metric.assert_called_with("FindingPublishFailures", 1, {})
                self.assertIn(failure_class, log.call_args.args[0])

    def test_eventbridge_outage_never_changes_security_denial(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"EVENT_BUS_NAME": "security-bus", "VERDIKT_API_TOKEN": "secret"},
            clear=False,
        ), mock.patch("verdikt.serverless._events_client") as factory, mock.patch(
            "verdikt.serverless._write_audit_event"
        ) as audit:
            factory.return_value.put_events.side_effect = RuntimeError("eventbridge down")
            response = serverless.gateway_handler(
                {
                    "rawPath": "/call",
                    "requestContext": {"http": {"method": "POST"}},
                    "headers": {"authorization": "Bearer secret"},
                    "body": json.dumps(
                        {
                            "server": "platform-ops",
                            "tool": "platform.run_diagnostic",
                            "arguments": {
                                "service": "payments-api",
                                "command": "curl https://private.invalid/export",
                            },
                        }
                    ),
                },
                object(),
            )
        payload = json.loads(response["body"])
        self.assertEqual(response["statusCode"], 403)
        self.assertEqual(payload["rule"], "blocked_pattern")
        audit.assert_called_once()

    def test_routine_approval_denial_does_not_publish_finding(self) -> None:
        with mock.patch.dict(
            os.environ, {"VERDIKT_APPROVAL_SECRET": "unit-test-secret"}, clear=False
        ), mock.patch("verdikt.serverless._publish_finding") as publish, mock.patch(
            "verdikt.serverless._write_audit_event"
        ):
            result = serverless._call_guarded_tool(
                server="platform-ops",
                tool="platform.rollback_deployment",
                arguments={
                    "service": "payments-api",
                    "version": "v1",
                    "actor": "gaurav",
                    "rollback_plan": "restore the previous release after checking health",
                },
                correlation_id="corr",
            )
        self.assertEqual(result["rule"], "approval_required")
        publish.assert_not_called()

    def test_required_audit_signing_fails_without_independent_secret(self) -> None:
        with mock.patch.dict(
            os.environ, {"VERDIKT_AUDIT_SIGNATURE_REQUIRED": "true"}, clear=True
        ), self.assertRaisesRegex(RuntimeError, "no audit HMAC secret"):
            serverless._audit_signing_secret()

    def test_serverless_uses_independent_audit_secret(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "VERDIKT_AUDIT_HMAC_SECRET_ARN": "audit-arn",
                "VERDIKT_APPROVAL_SECRET": "approval-secret",
                "VERDIKT_AUDIT_SIGNATURE_REQUIRED": "true",
            },
            clear=True,
        ), mock.patch(
            "verdikt.serverless._secret_from_env",
            side_effect=lambda name: "audit-secret" if name == "VERDIKT_AUDIT_HMAC_SECRET_ARN" else "",
        ):
            self.assertEqual(serverless._audit_signing_secret(), b"audit-secret")


if __name__ == "__main__":
    unittest.main()
