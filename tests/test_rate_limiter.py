from __future__ import annotations

import os
import sys
import types
import unittest
from unittest.mock import patch

from mcp_guard.rate_limiter import LocalRateLimiter, RedisRateLimiter, build_rate_limiter


class LocalRateLimiterTest(unittest.TestCase):
    def test_limit_blocks_after_threshold(self) -> None:
        limiter = LocalRateLimiter()

        self.assertTrue(limiter.allow("tool:platform.health", 2, 60))
        self.assertTrue(limiter.allow("tool:platform.health", 2, 60))
        self.assertFalse(limiter.allow("tool:platform.health", 2, 60))

    def test_unavailable_redis_falls_back_when_not_required(self) -> None:
        with patch.dict(
            os.environ,
            {
                "MCP_GUARD_REDIS_URL": "redis://unavailable:6379/0",
                "MCP_GUARD_REDIS_REQUIRED": "false",
            },
            clear=False,
        ), patch("mcp_guard.rate_limiter.RedisRateLimiter", side_effect=RuntimeError("unavailable")):
            limiter = build_rate_limiter()

        self.assertEqual(limiter.mode, "local-fallback")

    def test_unavailable_required_redis_fails_startup(self) -> None:
        with patch.dict(
            os.environ,
            {
                "MCP_GUARD_REDIS_URL": "redis://unavailable:6379/0",
                "MCP_GUARD_REDIS_REQUIRED": "true",
            },
            clear=False,
        ), patch("mcp_guard.rate_limiter.RedisRateLimiter", side_effect=RuntimeError("unavailable")):
            with self.assertRaisesRegex(RuntimeError, "unavailable"):
                build_rate_limiter()

    def test_redis_limiter_checks_backend_during_startup(self) -> None:
        class FakeRedisError(Exception):
            pass

        class FakeClient:
            def ping(self) -> None:
                raise FakeRedisError("connection refused")

        class FakeRedisFactory:
            @staticmethod
            def from_url(url: str, decode_responses: bool) -> FakeClient:
                return FakeClient()

        redis_module = types.SimpleNamespace(Redis=FakeRedisFactory, RedisError=FakeRedisError)
        with patch.dict(sys.modules, {"redis": redis_module}):
            with self.assertRaisesRegex(RuntimeError, "backend is unavailable"):
                RedisRateLimiter("redis://unavailable:6379/0")


if __name__ == "__main__":
    unittest.main()
