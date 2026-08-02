from __future__ import annotations

import json
import math
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable


class SecretBrokerError(RuntimeError):
    """Raised when a configured secret cannot be resolved safely."""


def read_aws_secret(
    secret_id: str,
    json_key: str = "",
    *,
    client: Any | None = None,
) -> str:
    if not secret_id.strip():
        raise SecretBrokerError("AWS secret identifier must not be empty")
    if client is None:
        try:
            import boto3
        except ImportError as exc:  # pragma: no cover - optional AWS profile
            raise SecretBrokerError(
                "AWS Secrets Manager requires the optional aws dependencies"
            ) from exc
        client = boto3.client("secretsmanager")
    try:
        response = client.get_secret_value(SecretId=secret_id)
    except Exception as exc:
        raise SecretBrokerError(f"AWS secret {secret_id!r} could not be retrieved") from exc
    value = response.get("SecretString")
    if not isinstance(value, str) or not value:
        raise SecretBrokerError(f"AWS secret {secret_id!r} has no SecretString or it is empty")
    return (
        _select_json_value(value, json_key, f"AWS secret {secret_id!r}")
        if json_key
        else value
    )


def read_vault_secret(
    path: str,
    json_key: str,
    *,
    opener: Callable[..., Any] | None = None,
) -> str:
    address = os.getenv("JUDIKT_VAULT_ADDR", "").strip()
    if not address:
        raise SecretBrokerError("JUDIKT_VAULT_ADDR is required for Vault secrets")
    endpoint = _vault_endpoint(address, path)
    if not json_key:
        raise SecretBrokerError("Vault secret sources require a json_key")
    token = resolve_configured_secret(
        direct_env="JUDIKT_VAULT_TOKEN",
        aws_secret_env="JUDIKT_VAULT_TOKEN_SECRET_ARN",
        json_key_env="JUDIKT_VAULT_TOKEN_SECRET_JSON_KEY",
        required=True,
        description="Vault client token",
        allow_vault=False,
    )
    request = urllib.request.Request(
        endpoint,
        headers={
            "Accept": "application/json",
            "User-Agent": "Judikt/secret-broker",
            "X-Vault-Token": token,
        },
        method="GET",
    )
    namespace = os.getenv("JUDIKT_VAULT_NAMESPACE", "").strip()
    if namespace:
        request.add_header("X-Vault-Namespace", namespace)
    timeout = _positive_float_env("JUDIKT_SECRET_TIMEOUT_SECONDS", 2.0)
    open_request = opener or urllib.request.urlopen
    try:
        with open_request(request, timeout=timeout) as response:
            status = int(getattr(response, "status", 200))
            if status < 200 or status >= 300:
                raise SecretBrokerError(f"Vault returned HTTP {status}")
            body = response.read(1_048_577)
    except urllib.error.HTTPError as exc:
        code = exc.code
        exc.close()
        raise SecretBrokerError(f"Vault returned HTTP {code}") from exc
    except urllib.error.URLError as exc:
        raise SecretBrokerError("Vault is unavailable") from exc
    except SecretBrokerError:
        raise
    except Exception as exc:
        raise SecretBrokerError("Vault request failed") from exc
    if len(body) > 1_048_576:
        raise SecretBrokerError("Vault response exceeded the 1 MiB safety limit")
    try:
        document = json.loads(body)
        data = document["data"]
        if isinstance(data, dict) and isinstance(data.get("data"), dict):
            data = data["data"]
        value = data[json_key]
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise SecretBrokerError(f"Vault secret does not contain JSON key {json_key!r}") from exc
    if not isinstance(value, str) or not value:
        raise SecretBrokerError(f"Vault JSON key {json_key!r} must contain a non-empty string")
    return value


def resolve_configured_secret(
    *,
    direct_env: str,
    aws_secret_env: str,
    vault_path_env: str = "",
    json_key_env: str = "",
    required: bool = False,
    description: str = "secret",
    allow_vault: bool = True,
) -> str:
    direct = os.getenv(direct_env, "")
    aws_id = os.getenv(aws_secret_env, "").strip()
    vault_path = os.getenv(vault_path_env, "").strip() if vault_path_env else ""
    configured = [
        name
        for name, value in (
            (direct_env, direct.strip()),
            (aws_secret_env, aws_id),
            (vault_path_env, vault_path),
        )
        if name and value
    ]
    if len(configured) > 1:
        raise SecretBrokerError(
            f"{description} has ambiguous sources configured: {', '.join(configured)}"
        )
    json_key = os.getenv(json_key_env, "").strip() if json_key_env else ""
    if direct.strip():
        return direct
    if aws_id:
        return read_aws_secret(aws_id, json_key)
    if vault_path:
        if not allow_vault:
            raise SecretBrokerError(f"{description} cannot recursively use Vault")
        return read_vault_secret(vault_path, json_key or "value")
    if required:
        sources = [direct_env, aws_secret_env]
        if vault_path_env and allow_vault:
            sources.append(vault_path_env)
        raise SecretBrokerError(f"{description} requires one of: {', '.join(sources)}")
    return ""


def _select_json_value(document: str, key: str, source: str) -> str:
    try:
        selected = json.loads(document)[key]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise SecretBrokerError(f"{source} does not contain JSON key {key!r}") from exc
    if not isinstance(selected, str) or not selected:
        raise SecretBrokerError(f"{source} JSON key {key!r} must contain a non-empty string")
    return selected


def _vault_endpoint(address: str, path: str) -> str:
    parsed = urllib.parse.urlparse(address)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise SecretBrokerError("JUDIKT_VAULT_ADDR must be an absolute HTTP(S) URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise SecretBrokerError(
            "JUDIKT_VAULT_ADDR must not contain credentials, query, or fragment"
        )
    loopback = parsed.hostname in {"127.0.0.1", "localhost", "::1"}
    if (
        parsed.scheme == "http"
        and not loopback
        and not _enabled("JUDIKT_VAULT_ALLOW_INSECURE_HTTP")
    ):
        raise SecretBrokerError("non-loopback Vault integration requires HTTPS")
    normalized_path = path.strip("/")
    segments = normalized_path.split("/")
    if not normalized_path or any(segment in {"", ".", ".."} for segment in segments):
        raise SecretBrokerError("Vault secret path must be a non-empty relative path")
    if "?" in normalized_path or "#" in normalized_path:
        raise SecretBrokerError("Vault secret path must not contain query or fragment data")
    encoded_path = urllib.parse.quote(normalized_path, safe="/-_.")
    return address.rstrip("/") + "/v1/" + encoded_path


def _positive_float_env(name: str, default: float) -> float:
    try:
        value = float(os.getenv(name, str(default)))
    except ValueError as exc:
        raise SecretBrokerError(f"{name} must be a positive finite number") from exc
    if not math.isfinite(value) or value <= 0:
        raise SecretBrokerError(f"{name} must be a positive finite number")
    return value


def _enabled(name: str) -> bool:
    return os.getenv(name, "").lower() in {"1", "true", "yes"}
