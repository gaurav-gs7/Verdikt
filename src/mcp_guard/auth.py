from __future__ import annotations

import base64
import dataclasses
import hashlib
import hmac
import json
import os
import re
import time
import urllib.parse
from typing import Any


class AuthError(ValueError):
    pass


OAUTH_SCOPE_PATTERN = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~:/-]+$")


@dataclasses.dataclass(frozen=True)
class AuthConfig:
    bearer_token: str = ""
    jwt_hs256_secret: str = ""
    jwt_issuer: str = ""
    jwt_audience: str = ""
    jwt_required_group: str = ""
    jwt_jwks_url: str = ""
    resource_uri: str = "http://127.0.0.1:8080/mcp"
    authorization_server: str = ""
    required_scopes: tuple[str, ...] = ("mcp:tools",)
    admin_scope: str = "mcp:admin"
    allowed_origins: tuple[str, ...] = ()

    @classmethod
    def from_env(cls) -> "AuthConfig":
        return cls(
            bearer_token=os.getenv("MCP_GUARD_HTTP_BEARER_TOKEN", ""),
            jwt_hs256_secret=os.getenv("MCP_GUARD_JWT_HS256_SECRET", ""),
            jwt_issuer=os.getenv("MCP_GUARD_JWT_ISSUER", ""),
            jwt_audience=os.getenv("MCP_GUARD_JWT_AUDIENCE", ""),
            jwt_required_group=os.getenv("MCP_GUARD_JWT_REQUIRED_GROUP", ""),
            jwt_jwks_url=os.getenv("MCP_GUARD_JWT_JWKS_URL", ""),
            resource_uri=os.getenv("MCP_GUARD_RESOURCE_URI", "http://127.0.0.1:8080/mcp"),
            authorization_server=os.getenv("MCP_GUARD_AUTHORIZATION_SERVER", ""),
            required_scopes=tuple(
                scope for scope in os.getenv("MCP_GUARD_REQUIRED_SCOPES", "mcp:tools").split() if scope
            ),
            admin_scope=os.getenv("MCP_GUARD_ADMIN_SCOPE", "mcp:admin"),
            allowed_origins=tuple(
                origin.strip().rstrip("/")
                for origin in os.getenv("MCP_GUARD_ALLOWED_ORIGINS", "").split(",")
                if origin.strip()
            ),
        )

    @property
    def enabled(self) -> bool:
        return bool(self.bearer_token or self.jwt_hs256_secret or self.jwt_jwks_url)

    @property
    def mode(self) -> str:
        modes = []
        if self.bearer_token:
            modes.append("bearer")
        if self.jwt_hs256_secret or self.jwt_jwks_url:
            modes.append("jwt")
        return "+".join(modes) if modes else "network-boundary"

    def validate_for_remote_server(self, *, require_auth: bool = False) -> None:
        if require_auth and not self.enabled:
            raise AuthError("remote MCP binding requires bearer or JWT authentication")
        if self.bearer_token and (self.jwt_hs256_secret or self.jwt_jwks_url):
            raise AuthError("static bearer and JWT authentication cannot be enabled together")
        if self.jwt_hs256_secret or self.jwt_jwks_url:
            if not self.jwt_issuer:
                raise AuthError("MCP_GUARD_JWT_ISSUER is required for remote JWT authentication")
            if not self.jwt_audience:
                raise AuthError("MCP_GUARD_JWT_AUDIENCE is required for remote JWT authentication")
            if not self.authorization_server:
                raise AuthError(
                    "MCP_GUARD_AUTHORIZATION_SERVER is required for remote JWT authentication"
                )
        parsed_resource = urllib.parse.urlparse(self.resource_uri)
        if not parsed_resource.hostname:
            raise AuthError("MCP_GUARD_RESOURCE_URI must be an absolute HTTP(S) URI")
        if parsed_resource.scheme != "https" and parsed_resource.hostname not in {"127.0.0.1", "localhost"}:
            raise AuthError("MCP_GUARD_RESOURCE_URI must use HTTPS except on localhost")
        if parsed_resource.fragment:
            raise AuthError("MCP_GUARD_RESOURCE_URI must not contain a fragment")
        for name, url in (
            ("MCP_GUARD_JWT_JWKS_URL", self.jwt_jwks_url),
            ("MCP_GUARD_AUTHORIZATION_SERVER", self.authorization_server),
        ):
            if url and not _is_secure_or_loopback_url(url):
                raise AuthError(f"{name} must use HTTPS except on localhost")
        for scope in (*self.required_scopes, self.admin_scope):
            if scope and not OAUTH_SCOPE_PATTERN.fullmatch(scope):
                raise AuthError(f"invalid OAuth scope configured: {scope!r}")
        for origin in self.allowed_origins:
            if _origin(origin) is None:
                raise AuthError(f"invalid allowed Origin: {origin!r}")

    def protected_resource_metadata(self) -> dict[str, Any]:
        metadata: dict[str, Any] = {
            "resource": self.resource_uri,
            "bearer_methods_supported": ["header"],
            "scopes_supported": list(dict.fromkeys((*self.required_scopes, self.admin_scope))),
        }
        if self.authorization_server:
            metadata["authorization_servers"] = [self.authorization_server]
        return metadata

    def bearer_challenge(self, metadata_url: str) -> str:
        challenge = f'Bearer resource_metadata="{metadata_url}"'
        if self.required_scopes:
            challenge += f', scope="{" ".join(self.required_scopes)}"'
        return challenge

    def protected_resource_metadata_url(self) -> str:
        parsed = urllib.parse.urlsplit(self.resource_uri)
        return urllib.parse.urlunsplit(
            (parsed.scheme, parsed.netloc, "/.well-known/oauth-protected-resource", "", "")
        )

    def origin_allowed(self, origin: str) -> bool:
        observed = _origin(origin)
        if observed is None:
            return False
        source = self.allowed_origins or (self.resource_uri,)
        configured = {_origin(candidate) for candidate in source}
        return observed in configured


@dataclasses.dataclass(frozen=True)
class AuthResult:
    subject: str
    claims: dict[str, Any]


class Authenticator:
    def __init__(self, config: AuthConfig) -> None:
        self.config = config
        self._jwks_client: Any | None = None

    @classmethod
    def from_env(cls) -> "Authenticator":
        return cls(AuthConfig.from_env())

    def authenticate(self, authorization: str) -> AuthResult:
        if not self.config.enabled:
            return AuthResult("anonymous", {})
        if not authorization.startswith("Bearer "):
            raise AuthError("missing bearer authorization header")
        token = authorization.removeprefix("Bearer ").strip()
        if self.config.bearer_token and hmac.compare_digest(token, self.config.bearer_token):
            return AuthResult("bearer-token", {"auth_type": "static_bearer"})
        if self.config.jwt_hs256_secret or self.config.jwt_jwks_url:
            return self._authenticate_jwt(token)
        raise AuthError("invalid bearer token")

    def _authenticate_jwt(self, token: str) -> AuthResult:
        if self.config.jwt_hs256_secret:
            claims = self._verify_hs256(token)
        else:
            claims = self._verify_with_pyjwt(token)
        self._validate_claims(claims)
        subject = str(claims.get("sub") or claims.get("username") or claims.get("email") or "jwt-subject")
        return AuthResult(subject, claims)

    def _verify_hs256(self, token: str) -> dict[str, Any]:
        header_b64, payload_b64, signature_b64 = _split_jwt(token)
        header = _json_b64url_decode(header_b64)
        if header.get("alg") != "HS256":
            raise AuthError("expected HS256 JWT")
        signed = f"{header_b64}.{payload_b64}".encode()
        expected = hmac.new(self.config.jwt_hs256_secret.encode(), signed, hashlib.sha256).digest()
        observed = _b64url_decode(signature_b64)
        if not hmac.compare_digest(expected, observed):
            raise AuthError("invalid JWT signature")
        claims = _json_b64url_decode(payload_b64)
        if not isinstance(claims, dict):
            raise AuthError("JWT payload must be an object")
        return claims

    def _verify_with_pyjwt(self, token: str) -> dict[str, Any]:
        try:
            import jwt
            from jwt import PyJWKClient
        except ImportError as exc:  # pragma: no cover - optional dependency path
            raise AuthError("OIDC/JWKS validation requires optional auth dependencies") from exc
        try:
            if self._jwks_client is None:
                self._jwks_client = PyJWKClient(self.config.jwt_jwks_url)
            signing_key = self._jwks_client.get_signing_key_from_jwt(token)
            options = {"verify_aud": bool(self.config.jwt_audience)}
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                audience=self.config.jwt_audience or None,
                issuer=self.config.jwt_issuer or None,
                options=options,
            )
        except jwt.PyJWTError as exc:
            raise AuthError("invalid JWT") from exc
        if not isinstance(claims, dict):
            raise AuthError("JWT payload must be an object")
        return claims

    def _validate_claims(self, claims: dict[str, Any]) -> None:
        now = int(time.time())
        exp = claims.get("exp")
        if exp is None:
            raise AuthError("JWT is missing required exp claim")
        if int(exp) <= now:
            raise AuthError("JWT is expired")
        nbf = claims.get("nbf")
        if nbf is not None and int(nbf) > now:
            raise AuthError("JWT is not active yet")
        if self.config.jwt_issuer and claims.get("iss") != self.config.jwt_issuer:
            raise AuthError("JWT issuer mismatch")
        if self.config.jwt_audience:
            audience = claims.get("aud")
            audiences = audience if isinstance(audience, list) else [audience]
            if self.config.jwt_audience not in audiences:
                raise AuthError("JWT audience mismatch")
        if self.config.jwt_required_group:
            groups = claims.get("cognito:groups") or claims.get("groups") or []
            if isinstance(groups, str):
                groups = [groups]
            if self.config.jwt_required_group not in groups:
                raise AuthError("JWT group requirement not satisfied")
        if self.config.required_scopes:
            presented = claims.get("scope", claims.get("scp", []))
            scopes = presented.split() if isinstance(presented, str) else list(presented or [])
            missing = sorted(set(self.config.required_scopes) - set(scopes))
            if missing:
                raise AuthError(f"JWT is missing required scopes: {', '.join(missing)}")


def create_hs256_jwt(claims: dict[str, Any], secret: str, header: dict[str, Any] | None = None) -> str:
    jwt_header = {"alg": "HS256", "typ": "JWT", **(header or {})}
    header_b64 = _b64url_json(jwt_header)
    payload_b64 = _b64url_json(claims)
    signed = f"{header_b64}.{payload_b64}".encode()
    signature = hmac.new(secret.encode(), signed, hashlib.sha256).digest()
    return f"{header_b64}.{payload_b64}.{_b64url_encode(signature)}"


def _split_jwt(token: str) -> tuple[str, str, str]:
    parts = token.split(".")
    if len(parts) != 3:
        raise AuthError("invalid JWT structure")
    return parts[0], parts[1], parts[2]


def _b64url_json(value: dict[str, Any]) -> str:
    return _b64url_encode(json.dumps(value, separators=(",", ":"), sort_keys=True).encode())


def _json_b64url_decode(value: str) -> Any:
    return json.loads(_b64url_decode(value))


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def _b64url_decode(value: str) -> bytes:
    padded = value + "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(padded.encode())


def _is_secure_or_loopback_url(value: str) -> bool:
    parsed = urllib.parse.urlparse(value)
    return bool(
        parsed.hostname
        and (
            parsed.scheme == "https"
            or (parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost"})
        )
    )


def _origin(value: str) -> str | None:
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError:
        return None
    default_port = 443 if parsed.scheme == "https" else 80
    suffix = "" if port == default_port else f":{port}"
    return f"{parsed.scheme}://{parsed.hostname.lower()}{suffix}"
