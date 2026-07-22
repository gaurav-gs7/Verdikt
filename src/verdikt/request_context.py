from __future__ import annotations

from contextvars import ContextVar, Token
import os
from typing import Any


_AUTHENTICATED_SUBJECT: ContextVar[str] = ContextVar("verdikt_authenticated_subject", default="")
_AUTHENTICATED_CLAIMS: ContextVar[dict[str, Any]] = ContextVar(
    "verdikt_authenticated_claims", default={}
)


def authenticated_subject() -> str:
    return _AUTHENTICATED_SUBJECT.get()


def bind_authenticated_subject(
    subject: str,
    claims: dict[str, Any] | None = None,
) -> tuple[Token[str], Token[dict[str, Any]]]:
    return _AUTHENTICATED_SUBJECT.set(subject), _AUTHENTICATED_CLAIMS.set(claims or {})


def reset_authenticated_subject(tokens: tuple[Token[str], Token[dict[str, Any]]]) -> None:
    subject_token, claims_token = tokens
    _AUTHENTICATED_CLAIMS.reset(claims_token)
    _AUTHENTICATED_SUBJECT.reset(subject_token)


def is_control_plane_admin() -> bool:
    claims = _AUTHENTICATED_CLAIMS.get()
    if not claims:
        return True
    if claims.get("auth_type") == "static_bearer":
        return True
    presented = claims.get("scope", claims.get("scp", []))
    scopes = presented.split() if isinstance(presented, str) else list(presented or [])
    required_scope = os.getenv("VERDIKT_ADMIN_SCOPE", "mcp:admin")
    if required_scope and required_scope in scopes:
        return True
    groups = claims.get("cognito:groups") or claims.get("groups") or []
    groups = [groups] if isinstance(groups, str) else list(groups)
    return os.getenv("VERDIKT_ADMIN_GROUP", "mcp-admin") in groups
