from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass
from typing import Any


TOKEN_VERSION = "gatetrace-approval-v1"
DEFAULT_DEV_SECRET = "local-dev-approval-secret-change-me"


@dataclass(frozen=True)
class ApprovalClaims:
    actor: str
    reason: str
    server: str
    tool: str
    arguments_hash: str
    expires_at: int


class ApprovalTokenError(ValueError):
    pass


class ApprovalAuthority:
    """Issues and verifies HMAC approval tokens for destructive tool calls."""

    def __init__(self, secret: str | None = None) -> None:
        self.secret = (secret or os.getenv("MCP_GUARD_APPROVAL_SECRET") or DEFAULT_DEV_SECRET).encode()

    def issue(
        self,
        *,
        actor: str,
        reason: str,
        server: str,
        tool: str,
        arguments: dict[str, Any],
        ttl_seconds: int = 300,
    ) -> str:
        return self.issue_digest(
            actor=actor,
            reason=reason,
            server=server,
            tool=tool,
            arguments_hash=arguments_hash(arguments),
            ttl_seconds=ttl_seconds,
        )

    def issue_digest(
        self,
        *,
        actor: str,
        reason: str,
        server: str,
        tool: str,
        arguments_hash: str,
        ttl_seconds: int = 300,
    ) -> str:
        claims = {
            "version": TOKEN_VERSION,
            "actor": actor,
            "reason": reason,
            "server": server,
            "tool": tool,
            "arguments_hash": arguments_hash,
            "expires_at": int(time.time()) + ttl_seconds,
        }
        payload = _b64(json.dumps(claims, sort_keys=True, separators=(",", ":")).encode())
        signature = _b64(hmac.new(self.secret, payload.encode(), hashlib.sha256).digest())
        return f"{payload}.{signature}"

    def verify(
        self,
        *,
        token: str,
        server: str,
        tool: str,
        arguments: dict[str, Any],
    ) -> ApprovalClaims:
        try:
            payload, signature = token.split(".", 1)
        except ValueError as exc:
            raise ApprovalTokenError("approval token is malformed") from exc
        expected = _b64(hmac.new(self.secret, payload.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(signature, expected):
            raise ApprovalTokenError("approval token signature is invalid")
        try:
            raw_claims = json.loads(_unb64(payload))
        except (json.JSONDecodeError, ValueError) as exc:
            raise ApprovalTokenError("approval token payload is invalid") from exc
        if raw_claims.get("version") != TOKEN_VERSION:
            raise ApprovalTokenError("approval token version is unsupported")
        if raw_claims.get("expires_at", 0) < int(time.time()):
            raise ApprovalTokenError("approval token is expired")
        if raw_claims.get("server") != server or raw_claims.get("tool") != tool:
            raise ApprovalTokenError("approval token is bound to a different tool")
        if raw_claims.get("arguments_hash") != arguments_hash(arguments):
            raise ApprovalTokenError("approval token is bound to different arguments")
        return ApprovalClaims(
            actor=raw_claims["actor"],
            reason=raw_claims["reason"],
            server=raw_claims["server"],
            tool=raw_claims["tool"],
            arguments_hash=raw_claims["arguments_hash"],
            expires_at=raw_claims["expires_at"],
        )


def arguments_hash(arguments: dict[str, Any]) -> str:
    canonical = {
        key: value
        for key, value in arguments.items()
        if key not in {"approved", "approval_token"}
    }
    encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
