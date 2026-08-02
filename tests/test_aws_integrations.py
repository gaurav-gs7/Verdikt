from __future__ import annotations

import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from judikt.audit_sink import S3AuditSink
from judikt.secrets import SecretBrokerError, read_aws_secret
from judikt.upstreams import load_upstream_servers


class FakeAWSClient:
    def __init__(self, secret: str = "") -> None:
        self.secret = secret
        self.calls: list[dict[str, object]] = []

    def get_secret_value(self, **arguments: object) -> dict[str, str]:
        self.calls.append(arguments)
        return {"SecretString": self.secret}

    def put_object(self, **arguments: object) -> None:
        self.calls.append(arguments)


class AWSIntegrationTest(unittest.TestCase):
    def test_botocore_stubber_validates_real_secrets_manager_contract(self) -> None:
        import boto3
        from botocore.stub import Stubber

        client = boto3.client(
            "secretsmanager",
            region_name="us-east-1",
            aws_access_key_id="test-access-key",
            aws_secret_access_key="test-secret-key",
        )
        with Stubber(client) as stubber:
            stubber.add_response(
                "get_secret_value",
                {"SecretString": '{"token":"stubber-secret"}'},
                {"SecretId": "judikt/test"},
            )
            self.assertEqual(
                read_aws_secret("judikt/test", "token", client=client),
                "stubber-secret",
            )

        with Stubber(client) as stubber:
            stubber.add_client_error(
                "get_secret_value",
                service_error_code="ResourceNotFoundException",
                service_message="private AWS service detail",
                expected_params={"SecretId": "judikt/missing"},
            )
            with self.assertRaisesRegex(SecretBrokerError, "could not be retrieved") as raised:
                read_aws_secret("judikt/missing", client=client)
            self.assertNotIn("private AWS service detail", str(raised.exception))

    def test_resolves_upstream_credential_from_secrets_manager(self) -> None:
        client = FakeAWSClient('{"token":"operator-managed-token"}')
        boto3 = types.SimpleNamespace(client=lambda service: client)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "upstreams.json"
            path.write_text(
                json.dumps(
                    {
                        "servers": {
                            "github": {
                                "command": ["github-mcp-server"],
                                "env": {
                                    "GITHUB_TOKEN": {
                                        "from_aws_secret": "judikt/upstreams/github",
                                        "json_key": "token",
                                    }
                                },
                            }
                        }
                    }
                )
            )

            with patch.dict(sys.modules, {"boto3": boto3}):
                servers = load_upstream_servers(path)

        self.assertEqual(servers[0].environment["GITHUB_TOKEN"], "operator-managed-token")
        self.assertEqual(client.calls, [{"SecretId": "judikt/upstreams/github"}])

    def test_s3_sink_uploads_encrypted_redacted_envelope(self) -> None:
        client = FakeAWSClient()
        boto3 = types.SimpleNamespace(client=lambda service: client)
        event = {
            "created_at": "2026-07-20T12:30:00+00:00",
            "tool": "platform.health",
            "arguments": {"token": "[REDACTED]"},
        }

        with patch.dict(sys.modules, {"boto3": boto3}):
            sink = S3AuditSink("audit-bucket", "judikt/audit")
            sink.write(event)

        request = client.calls[0]
        self.assertEqual(request["Bucket"], "audit-bucket")
        self.assertTrue(str(request["Key"]).startswith("judikt/audit/date=2026-07-20/"))
        self.assertEqual(request["ContentType"], "application/json")
        self.assertEqual(request["ServerSideEncryption"], "AES256")
        self.assertEqual(json.loads(request["Body"]), event)


if __name__ == "__main__":
    unittest.main()
