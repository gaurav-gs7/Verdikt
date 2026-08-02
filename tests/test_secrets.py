from __future__ import annotations

import builtins
import json
import os
import sys
import tempfile
import types
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

from judikt.secrets import (
    SecretBrokerError,
    read_aws_secret,
    read_vault_secret,
    resolve_configured_secret,
)
from judikt.upstreams import UpstreamConfigError, load_upstream_servers


class _AWSClient:
    def __init__(self, response: dict[str, object]) -> None:
        self.response = response
        self.calls: list[str] = []

    def get_secret_value(self, SecretId: str) -> dict[str, object]:
        self.calls.append(SecretId)
        return self.response


class _VaultResponse:
    def __init__(
        self,
        document: object | None = None,
        *,
        body: bytes | None = None,
        status: int = 200,
    ) -> None:
        self.status = status
        self.body = body if body is not None else json.dumps(document).encode()

    def read(self, limit: int) -> bytes:
        return self.body[:limit]

    def __enter__(self) -> "_VaultResponse":
        return self

    def __exit__(self, *args: object) -> None:
        return None


class SecretBrokerTest(unittest.TestCase):
    def test_aws_secret_supports_raw_and_json_values(self) -> None:
        raw = _AWSClient({"SecretString": "raw-token"})
        self.assertEqual(read_aws_secret("raw-secret", client=raw), "raw-token")

        document = _AWSClient({"SecretString": '{"token":"selected-token"}'})
        self.assertEqual(
            read_aws_secret("json-secret", "token", client=document),
            "selected-token",
        )
        self.assertEqual(document.calls, ["json-secret"])

    def test_aws_secret_rejects_empty_identifier_and_normalizes_client_failure(self) -> None:
        with self.assertRaisesRegex(SecretBrokerError, "must not be empty"):
            read_aws_secret("  ", client=_AWSClient({"SecretString": "unused"}))

        class FailingClient:
            def get_secret_value(self, SecretId: str) -> dict[str, object]:
                raise RuntimeError("private AWS diagnostic")

        with self.assertRaisesRegex(SecretBrokerError, "could not be retrieved") as raised:
            read_aws_secret("secret-id", client=FailingClient())
        self.assertNotIn("private AWS diagnostic", str(raised.exception))

    def test_aws_secret_without_optional_dependency_has_actionable_error(self) -> None:
        real_import = builtins.__import__

        def blocked_import(name: str, *args: object, **kwargs: object) -> object:
            if name == "boto3":
                raise ImportError("synthetic missing dependency")
            return real_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=blocked_import), self.assertRaisesRegex(
            SecretBrokerError, "optional aws dependencies"
        ):
            read_aws_secret("secret-id")

    def test_aws_secret_rejects_binary_missing_and_non_string_json_values(self) -> None:
        cases = [
            ({"SecretBinary": b"secret"}, "has no SecretString"),
            ({"SecretString": "{}"}, "does not contain JSON key"),
            ({"SecretString": '{"token":123}'}, "non-empty string"),
        ]
        for response, message in cases:
            with self.subTest(response=response), self.assertRaisesRegex(
                SecretBrokerError, message
            ):
                read_aws_secret("secret-id", "token", client=_AWSClient(response))

    def test_vault_kv_v2_resolves_secret_with_namespace_and_safe_headers(self) -> None:
        captured: list[dict[str, object]] = []

        def opener(request: object, timeout: float) -> _VaultResponse:
            captured.append(
                {
                    "url": request.full_url,
                    "headers": {key.lower(): value for key, value in request.header_items()},
                    "timeout": timeout,
                }
            )
            return _VaultResponse({"data": {"data": {"token": "vault-token"}}})

        with patch.dict(
            os.environ,
            {
                "JUDIKT_VAULT_ADDR": "https://vault.example.test",
                "JUDIKT_VAULT_TOKEN": "vault-client-token",
                "JUDIKT_VAULT_NAMESPACE": "platform",
                "JUDIKT_SECRET_TIMEOUT_SECONDS": "1.5",
            },
            clear=True,
        ):
            value = read_vault_secret("secret/data/judikt/slack", "token", opener=opener)

        self.assertEqual(value, "vault-token")
        self.assertEqual(
            captured[0]["url"],
            "https://vault.example.test/v1/secret/data/judikt/slack",
        )
        self.assertEqual(captured[0]["headers"]["x-vault-token"], "vault-client-token")
        self.assertEqual(captured[0]["headers"]["x-vault-namespace"], "platform")
        self.assertEqual(captured[0]["timeout"], 1.5)

    def test_vault_requires_an_address_before_resolving_credentials(self) -> None:
        with patch.dict(os.environ, {"JUDIKT_VAULT_TOKEN": "token"}, clear=True), self.assertRaisesRegex(
            SecretBrokerError, "JUDIKT_VAULT_ADDR"
        ):
            read_vault_secret("secret/data/app", "value")

    def test_vault_supports_kv_v1_and_normalizes_network_failures(self) -> None:
        environment = {
            "JUDIKT_VAULT_ADDR": "http://127.0.0.1:8200",
            "JUDIKT_VAULT_TOKEN": "development-token",
        }
        with patch.dict(os.environ, environment, clear=True):
            self.assertEqual(
                read_vault_secret(
                    "secret/judikt",
                    "value",
                    opener=lambda request, timeout: _VaultResponse(
                        {"data": {"value": "kv-v1-secret"}}
                    ),
                ),
                "kv-v1-secret",
            )
            with self.assertRaisesRegex(SecretBrokerError, "unavailable"):
                read_vault_secret(
                    "secret/judikt",
                    "value",
                    opener=lambda request, timeout: (_ for _ in ()).throw(
                        urllib.error.URLError("private connection detail")
                    ),
                )

    def test_vault_rejects_non_success_malformed_oversized_and_non_string_responses(self) -> None:
        environment = {
            "JUDIKT_VAULT_ADDR": "https://vault.example.test",
            "JUDIKT_VAULT_TOKEN": "token",
        }
        cases = [
            (_VaultResponse({"errors": ["denied"]}, status=403), "HTTP 403"),
            (_VaultResponse(body=b"not-json"), "does not contain JSON key"),
            (_VaultResponse({"data": {"data": {"value": 123}}}), "non-empty string"),
            (_VaultResponse({"data": {"data": {"value": ""}}}), "non-empty string"),
            (_VaultResponse(body=b"x" * 1_048_577), "1 MiB safety limit"),
        ]
        with patch.dict(os.environ, environment, clear=True):
            for response, message in cases:
                with self.subTest(message=message), self.assertRaisesRegex(
                    SecretBrokerError, message
                ):
                    read_vault_secret(
                        "secret/data/app",
                        "value",
                        opener=lambda request, timeout, current=response: current,
                    )

    def test_vault_normalizes_http_and_unexpected_client_failures(self) -> None:
        environment = {
            "JUDIKT_VAULT_ADDR": "https://vault.example.test",
            "JUDIKT_VAULT_TOKEN": "token",
        }
        failures = [
            (
                urllib.error.HTTPError(
                    "https://vault.example.test/v1/secret/data/app",
                    503,
                    "private response",
                    {},
                    None,
                ),
                "HTTP 503",
            ),
            (RuntimeError("private client failure"), "Vault request failed"),
        ]
        with patch.dict(os.environ, environment, clear=True):
            for failure, message in failures:
                with self.subTest(message=message), self.assertRaisesRegex(
                    SecretBrokerError, message
                ) as raised:
                    read_vault_secret(
                        "secret/data/app",
                        "value",
                        opener=lambda request, timeout, current=failure: (_ for _ in ()).throw(
                            current
                        ),
                    )
                self.assertNotIn("private client failure", str(raised.exception))

    def test_vault_timeout_configuration_must_be_positive_and_finite(self) -> None:
        for value in ("bad", "0", "-1", "nan", "inf"):
            with self.subTest(value=value), patch.dict(
                os.environ,
                {
                    "JUDIKT_VAULT_ADDR": "https://vault.example.test",
                    "JUDIKT_VAULT_TOKEN": "token",
                    "JUDIKT_SECRET_TIMEOUT_SECONDS": value,
                },
                clear=True,
            ), self.assertRaisesRegex(SecretBrokerError, "positive finite"):
                read_vault_secret(
                    "secret/data/app",
                    "value",
                    opener=lambda request, timeout: _VaultResponse(
                        {"data": {"data": {"value": "unused"}}}
                    ),
                )

    def test_vault_client_token_can_be_bootstrapped_from_aws_secret(self) -> None:
        client = _AWSClient({"SecretString": '{"token":"aws-backed-vault-token"}'})
        boto3 = types.SimpleNamespace(client=lambda service: client)
        observed_headers: dict[str, str] = {}

        def opener(request: object, timeout: float) -> _VaultResponse:
            observed_headers.update(
                {key.lower(): value for key, value in request.header_items()}
            )
            return _VaultResponse({"data": {"data": {"value": "application-secret"}}})

        with patch.dict(sys.modules, {"boto3": boto3}), patch.dict(
            os.environ,
            {
                "JUDIKT_VAULT_ADDR": "https://vault.example.test",
                "JUDIKT_VAULT_TOKEN_SECRET_ARN": "vault-token-secret",
                "JUDIKT_VAULT_TOKEN_SECRET_JSON_KEY": "token",
            },
            clear=True,
        ):
            result = read_vault_secret("secret/data/app", "value", opener=opener)

        self.assertEqual(result, "application-secret")
        self.assertEqual(observed_headers["x-vault-token"], "aws-backed-vault-token")
        self.assertEqual(client.calls, ["vault-token-secret"])

    def test_vault_rejects_unsafe_addresses_paths_and_responses(self) -> None:
        invalid_addresses = [
            "http://vault.example.test",
            "ftp://vault.example.test",
            "https://user:pass@vault.example.test",
            "https://vault.example.test?token=secret",
        ]
        for address in invalid_addresses:
            with self.subTest(address=address), patch.dict(
                os.environ,
                {"JUDIKT_VAULT_ADDR": address, "JUDIKT_VAULT_TOKEN": "token"},
                clear=True,
            ), self.assertRaises(SecretBrokerError):
                read_vault_secret("secret/data/app", "value")

        with patch.dict(
            os.environ,
            {
                "JUDIKT_VAULT_ADDR": "https://vault.example.test",
                "JUDIKT_VAULT_TOKEN": "token",
            },
            clear=True,
        ):
            for path in ("", "../secret", "secret//value", "secret/value?raw=true"):
                with self.subTest(path=path), self.assertRaises(SecretBrokerError):
                    read_vault_secret(path, "value")
            with self.assertRaisesRegex(SecretBrokerError, "does not contain JSON key"):
                read_vault_secret(
                    "secret/data/app",
                    "missing",
                    opener=lambda request, timeout: _VaultResponse({"data": {"data": {}}}),
                )

        with patch.dict(
            os.environ,
            {
                "JUDIKT_VAULT_ADDR": "http://vault.example.test/base",
                "JUDIKT_VAULT_TOKEN": "token",
                "JUDIKT_VAULT_ALLOW_INSECURE_HTTP": "true",
            },
            clear=True,
        ):
            captured: list[str] = []
            value = read_vault_secret(
                "secret/data/app name",
                "value",
                opener=lambda request, timeout: captured.append(request.full_url)
                or _VaultResponse({"data": {"data": {"value": "allowed"}}}),
            )
        self.assertEqual(value, "allowed")
        self.assertEqual(
            captured,
            ["http://vault.example.test/base/v1/secret/data/app%20name"],
        )

    def test_configured_secret_rejects_ambiguous_sources(self) -> None:
        with patch.dict(
            os.environ,
            {"DIRECT_SECRET": "direct", "AWS_SECRET": "secret-id"},
            clear=True,
        ), self.assertRaisesRegex(SecretBrokerError, "ambiguous sources"):
            resolve_configured_secret(
                direct_env="DIRECT_SECRET",
                aws_secret_env="AWS_SECRET",
                description="test secret",
            )

    def test_configured_secret_preserves_direct_value_and_handles_vault_policy(self) -> None:
        with patch.dict(os.environ, {"DIRECT_SECRET": "  exact secret  "}, clear=True):
            self.assertEqual(
                resolve_configured_secret(
                    direct_env="DIRECT_SECRET",
                    aws_secret_env="AWS_SECRET",
                ),
                "  exact secret  ",
            )

        with patch.dict(
            os.environ,
            {"VAULT_SECRET": "secret/data/app"},
            clear=True,
        ), self.assertRaisesRegex(SecretBrokerError, "cannot recursively use Vault"):
            resolve_configured_secret(
                direct_env="DIRECT_SECRET",
                aws_secret_env="AWS_SECRET",
                vault_path_env="VAULT_SECRET",
                allow_vault=False,
                description="recursive secret",
            )

        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(
                resolve_configured_secret(
                    direct_env="DIRECT_SECRET",
                    aws_secret_env="AWS_SECRET",
                ),
                "",
            )

        with patch.dict(os.environ, {}, clear=True), self.assertRaisesRegex(
            SecretBrokerError, "requires one of"
        ):
            resolve_configured_secret(
                direct_env="DIRECT_SECRET",
                aws_secret_env="AWS_SECRET",
                vault_path_env="VAULT_SECRET",
                required=True,
                description="test secret",
            )

        with patch.dict(
            os.environ, {"VAULT_SECRET": "secret/data/app"}, clear=True
        ), patch("judikt.secrets.read_vault_secret", return_value="vault-value") as reader:
            self.assertEqual(
                resolve_configured_secret(
                    direct_env="DIRECT_SECRET",
                    aws_secret_env="AWS_SECRET",
                    vault_path_env="VAULT_SECRET",
                ),
                "vault-value",
            )
        reader.assert_called_once_with("secret/data/app", "value")

        with patch.dict(os.environ, {}, clear=True), self.assertRaisesRegex(
            SecretBrokerError, r"DIRECT_SECRET, AWS_SECRET$"
        ):
            resolve_configured_secret(
                direct_env="DIRECT_SECRET",
                aws_secret_env="AWS_SECRET",
                vault_path_env="VAULT_SECRET",
                required=True,
                allow_vault=False,
                description="non-recursive secret",
            )

    def test_upstream_registry_resolves_vault_credential_end_to_end(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "upstreams.json"
            path.write_text(
                json.dumps(
                    {
                        "servers": {
                            "company": {
                                "command": ["company-mcp-server"],
                                "env": {
                                    "UPSTREAM_API_TOKEN": {
                                        "from_vault": "secret/data/judikt/company",
                                        "json_key": "token",
                                    }
                                },
                            }
                        }
                    }
                )
            )
            with patch.dict(
                os.environ,
                {
                    "JUDIKT_VAULT_ADDR": "https://vault.example.test",
                    "JUDIKT_VAULT_TOKEN": "vault-client-token",
                },
                clear=True,
            ), patch(
                "judikt.secrets.urllib.request.urlopen",
                return_value=_VaultResponse(
                    {"data": {"data": {"token": "operator-managed-token"}}}
                ),
            ):
                servers = load_upstream_servers(path)

        self.assertEqual(
            servers[0].environment["UPSTREAM_API_TOKEN"],
            "operator-managed-token",
        )

    def test_upstream_registry_rejects_ambiguous_or_unknown_secret_sources(self) -> None:
        invalid_sources = [
            {"from_env": "TOKEN", "from_aws_secret": "secret-id"},
            {"from_env": "TOKEN", "unknown_source": "value"},
            {"from_env": "TOKEN", "json_key": "token"},
            {"from_vault": "secret/data/app"},
        ]
        for index, source in enumerate(invalid_sources):
            with self.subTest(source=source), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "upstreams.json"
                path.write_text(
                    json.dumps(
                        {
                            "servers": {
                                "company": {
                                    "command": ["company-mcp-server"],
                                    "env": {"UPSTREAM_API_TOKEN": source},
                                }
                            }
                        }
                    )
                )
                environment = {"TOKEN": f"token-{index}"}
                if "from_vault" in source:
                    environment.update(
                        {
                            "JUDIKT_VAULT_ADDR": "https://vault.example.test",
                            "JUDIKT_VAULT_TOKEN": "vault-client-token",
                        }
                    )
                with patch.dict(os.environ, environment, clear=True), self.assertRaises(
                    UpstreamConfigError
                ):
                    load_upstream_servers(path)


if __name__ == "__main__":
    unittest.main()
