from __future__ import annotations

import hashlib
import hmac
import json
import tempfile
import time
import unittest
import urllib.parse
from pathlib import Path
from unittest.mock import patch

from verdikt.approval import ApprovalAuthority
from verdikt.slack_approval import SlackApprovalError, SlackApprovalWorkflow


class SlackApprovalWorkflowTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.environment = patch.dict(
            "os.environ",
            {
                "VERDIKT_SLACK_WEBHOOK_URL": "https://hooks.slack.test/services/example",
                "VERDIKT_SLACK_SIGNING_SECRET": "slack-signing-secret",
                "VERDIKT_SLACK_APPROVER_IDS": "U-ONCALL",
            },
        )
        self.environment.start()
        self.authority = ApprovalAuthority("approval-secret")
        self.workflow = SlackApprovalWorkflow(
            Path(self.temp_dir.name) / "approvals.db",
            self.authority,
        )
        self.notify = patch.object(self.workflow, "_notify")
        self.notify.start()

    def tearDown(self) -> None:
        self.notify.stop()
        self.workflow.close()
        self.environment.stop()
        self.temp_dir.cleanup()

    def test_approved_token_is_returned_only_to_requester_and_bound_to_arguments(self) -> None:
        arguments = {
            "service": "payments-api",
            "actor": "sre-oncall",
            "rollback_plan": "restore the previous release when health checks fail",
        }
        requested = self.workflow.request(
            requester="sre-oncall",
            reason="elevated 5xx",
            server="platform-ops",
            tool="platform.restart_deployment",
            arguments=arguments,
            safe_arguments=arguments,
        )
        body, headers = self._signed_action(requested["request_id"], "approve", "U-ONCALL")

        response = self.workflow.handle_action(headers, body)
        status = self.workflow.status(requested["request_id"], "sre-oncall")

        self.assertIn("approved", response["text"])
        self.assertEqual(status["status"], "APPROVED")
        self.authority.verify(
            token=status["approval_token"],
            server="platform-ops",
            tool="platform.restart_deployment",
            arguments=arguments,
        )
        with self.assertRaisesRegex(SlackApprovalError, "different authenticated subject"):
            self.workflow.status(requested["request_id"], "readonly")

    def test_rejects_invalid_signature_and_unapproved_slack_user(self) -> None:
        requested = self.workflow.request(
            requester="sre-oncall",
            reason="restart",
            server="platform-ops",
            tool="platform.restart_deployment",
            arguments={"actor": "sre-oncall"},
            safe_arguments={"actor": "sre-oncall"},
        )
        body, headers = self._signed_action(requested["request_id"], "approve", "U-NOT-ALLOWED")

        with self.assertRaisesRegex(SlackApprovalError, "not an authorized approver"):
            self.workflow.handle_action(headers, body)

        headers["x-slack-signature"] = "v0=invalid"
        with self.assertRaisesRegex(SlackApprovalError, "signature is invalid"):
            self.workflow.handle_action(headers, body)

    def test_deduplicates_identical_pending_requests(self) -> None:
        request = {
            "requester": "sre-oncall",
            "reason": "restart",
            "server": "platform-ops",
            "tool": "platform.restart_deployment",
            "arguments": {"actor": "sre-oncall"},
            "safe_arguments": {"actor": "sre-oncall"},
        }

        first = self.workflow.request(**request)
        second = self.workflow.request(**request)

        self.assertEqual(second["request_id"], first["request_id"])
        self.assertTrue(second["deduplicated"])

    @staticmethod
    def _signed_action(request_id: str, decision: str, user_id: str) -> tuple[str, dict[str, str]]:
        payload = {
            "user": {"id": user_id},
            "actions": [
                {
                    "value": json.dumps({"request_id": request_id, "decision": decision}),
                }
            ],
        }
        body = urllib.parse.urlencode({"payload": json.dumps(payload)})
        timestamp = str(int(time.time()))
        base = f"v0:{timestamp}:{body}".encode()
        signature = "v0=" + hmac.new(
            b"slack-signing-secret", base, hashlib.sha256
        ).hexdigest()
        return body, {
            "x-slack-request-timestamp": timestamp,
            "x-slack-signature": signature,
        }


if __name__ == "__main__":
    unittest.main()
