from __future__ import annotations

import unittest

from mcp_guard.rate_limiter import LocalRateLimiter


class LocalRateLimiterTest(unittest.TestCase):
    def test_limit_blocks_after_threshold(self) -> None:
        limiter = LocalRateLimiter()

        self.assertTrue(limiter.allow("tool:platform.health", 2, 60))
        self.assertTrue(limiter.allow("tool:platform.health", 2, 60))
        self.assertFalse(limiter.allow("tool:platform.health", 2, 60))


if __name__ == "__main__":
    unittest.main()
