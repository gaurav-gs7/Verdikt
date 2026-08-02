from __future__ import annotations

import os
import time
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor

from judikt.rate_limiter import RedisRateLimiter


@unittest.skipUnless(os.getenv("JUDIKT_TEST_REDIS_URL"), "integration Redis URL is not configured")
class RedisRateLimiterIntegrationTest(unittest.TestCase):
    def test_two_instances_share_an_atomic_limit(self) -> None:
        url = os.environ["JUDIKT_TEST_REDIS_URL"]
        prefix = f"judikt:test:{uuid.uuid4()}"
        first = RedisRateLimiter(url, prefix=prefix)
        second = RedisRateLimiter(url, prefix=prefix)

        self.assertTrue(first.allow("actor:sre-oncall:tool:restart", 2, 60))
        self.assertTrue(second.allow("actor:sre-oncall:tool:restart", 2, 60))
        self.assertFalse(first.allow("actor:sre-oncall:tool:restart", 2, 60))

    def test_concurrent_instances_never_exceed_limit(self) -> None:
        url = os.environ["JUDIKT_TEST_REDIS_URL"]
        prefix = f"judikt:test:{uuid.uuid4()}"
        limiters = [RedisRateLimiter(url, prefix=prefix) for _ in range(4)]
        with ThreadPoolExecutor(max_workers=20) as executor:
            outcomes = list(
                executor.map(
                    lambda index: limiters[index % len(limiters)].allow("shared-actor", 13, 60),
                    range(60),
                )
            )
        self.assertEqual(sum(outcomes), 13)

    def test_counter_expires_and_hashed_key_has_bounded_ttl(self) -> None:
        import redis

        url = os.environ["JUDIKT_TEST_REDIS_URL"]
        prefix = f"judikt:test:{uuid.uuid4()}"
        limiter = RedisRateLimiter(url, prefix=prefix)
        actor = "actor:private-name:tool:restart"
        self.assertTrue(limiter.allow(actor, 1, 1))
        self.assertFalse(limiter.allow(actor, 1, 1))
        client = redis.Redis.from_url(url, decode_responses=True)
        keys = client.keys(f"{prefix}:*")
        self.assertEqual(len(keys), 1)
        self.assertNotIn("private-name", keys[0])
        ttl = client.pttl(keys[0])
        self.assertGreater(ttl, 0)
        self.assertLessEqual(ttl, 1000)
        time.sleep(1.05)
        self.assertTrue(limiter.allow(actor, 1, 1))


if __name__ == "__main__":
    unittest.main()
