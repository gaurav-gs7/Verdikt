from __future__ import annotations

import time
import unittest

from mcp_guard.auth import AuthConfig, AuthError, Authenticator, create_hs256_jwt
from mcp_guard.request_context import (
    bind_authenticated_subject,
    is_control_plane_admin,
    reset_authenticated_subject,
)


class AuthenticatorTest(unittest.TestCase):
    def test_hs256_jwt_validates_issuer_audience_and_group(self) -> None:
        secret = "unit-test-jwt-secret"
        token = create_hs256_jwt(
            {
                "sub": "sre-oncall",
                "iss": "https://issuer.example.test",
                "aud": "mcp-guard",
                "exp": int(time.time()) + 300,
                "groups": ["sre"],
                "scope": "mcp:tools",
            },
            secret,
        )
        authenticator = Authenticator(
            AuthConfig(
                jwt_hs256_secret=secret,
                jwt_issuer="https://issuer.example.test",
                jwt_audience="mcp-guard",
                jwt_required_group="sre",
            )
        )

        result = authenticator.authenticate(f"Bearer {token}")

        self.assertEqual(result.subject, "sre-oncall")
        self.assertEqual(result.claims["aud"], "mcp-guard")

    def test_hs256_jwt_rejects_wrong_group(self) -> None:
        secret = "unit-test-jwt-secret"
        token = create_hs256_jwt(
            {
                "sub": "readonly",
                "exp": int(time.time()) + 300,
                "groups": ["readonly"],
            },
            secret,
        )
        authenticator = Authenticator(
            AuthConfig(jwt_hs256_secret=secret, jwt_required_group="sre", required_scopes=())
        )

        with self.assertRaises(AuthError):
            authenticator.authenticate(f"Bearer {token}")

    def test_static_bearer_still_works(self) -> None:
        authenticator = Authenticator(AuthConfig(bearer_token="local-token"))

        result = authenticator.authenticate("Bearer local-token")

        self.assertEqual(result.subject, "bearer-token")

    def test_jwt_rejects_missing_required_scope(self) -> None:
        secret = "unit-test-jwt-secret"
        token = create_hs256_jwt(
            {"sub": "sre-oncall", "aud": "mcp-guard", "exp": int(time.time()) + 300},
            secret,
        )
        authenticator = Authenticator(
            AuthConfig(jwt_hs256_secret=secret, jwt_audience="mcp-guard")
        )

        with self.assertRaisesRegex(AuthError, "missing required scopes"):
            authenticator.authenticate(f"Bearer {token}")

    def test_remote_jwt_configuration_requires_audience(self) -> None:
        config = AuthConfig(jwt_hs256_secret="secret", jwt_issuer="https://issuer.example.test")

        with self.assertRaisesRegex(AuthError, "JWT_AUDIENCE"):
            config.validate_for_remote_server()

    def test_remote_jwt_configuration_requires_issuer(self) -> None:
        config = AuthConfig(jwt_hs256_secret="secret", jwt_audience="mcp-resource")

        with self.assertRaisesRegex(AuthError, "JWT_ISSUER"):
            config.validate_for_remote_server()

    def test_jwt_requires_expiry(self) -> None:
        secret = "unit-test-jwt-secret"
        token = create_hs256_jwt(
            {"sub": "sre-oncall", "aud": "mcp-guard", "scope": "mcp:tools"},
            secret,
        )
        authenticator = Authenticator(
            AuthConfig(jwt_hs256_secret=secret, jwt_audience="mcp-guard")
        )

        with self.assertRaisesRegex(AuthError, "exp claim"):
            authenticator.authenticate(f"Bearer {token}")

    def test_protected_resource_metadata_advertises_resource_and_authorization_server(self) -> None:
        config = AuthConfig(
            resource_uri="https://guard.example.test/mcp",
            authorization_server="https://auth.example.test",
        )

        metadata = config.protected_resource_metadata()

        self.assertEqual(metadata["resource"], "https://guard.example.test/mcp")
        self.assertEqual(metadata["authorization_servers"], ["https://auth.example.test"])
        self.assertEqual(metadata["scopes_supported"], ["mcp:tools", "mcp:admin"])

    def test_remote_binding_requires_authentication(self) -> None:
        with self.assertRaisesRegex(AuthError, "requires bearer or JWT"):
            AuthConfig().validate_for_remote_server(require_auth=True)

    def test_static_bearer_and_jwt_cannot_be_combined(self) -> None:
        config = AuthConfig(
            bearer_token="lab-token",
            jwt_hs256_secret="jwt-secret",
            jwt_issuer="https://issuer.example.test",
            jwt_audience="mcp-resource",
        )

        with self.assertRaisesRegex(AuthError, "cannot be enabled together"):
            config.validate_for_remote_server()

    def test_control_plane_admin_requires_admin_scope_or_group_for_jwt(self) -> None:
        normal = bind_authenticated_subject(
            "sre-oncall", {"sub": "sre-oncall", "scope": "mcp:tools", "groups": ["sre"]}
        )
        try:
            self.assertFalse(is_control_plane_admin())
        finally:
            reset_authenticated_subject(normal)

        admin = bind_authenticated_subject(
            "platform-admin",
            {"sub": "platform-admin", "scope": "mcp:tools mcp:admin"},
        )
        try:
            self.assertTrue(is_control_plane_admin())
        finally:
            reset_authenticated_subject(admin)


if __name__ == "__main__":
    unittest.main()
