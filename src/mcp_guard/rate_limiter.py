from __future__ import annotations

import dataclasses
import os
import time
from collections import defaultdict, deque
from typing import Protocol


class RateLimiter(Protocol):
    mode: str

    def allow(self, key: str, limit: int, window_seconds: int) -> bool:
        ...


@dataclasses.dataclass
class LocalRateLimiter:
    mode: str = "local"

    def __post_init__(self) -> None:
        self._calls: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str, limit: int, window_seconds: int) -> bool:
        now = time.monotonic()
        calls = self._calls[key]
        while calls and calls[0] <= now - window_seconds:
            calls.popleft()
        if len(calls) >= limit:
            return False
        calls.append(now)
        return True


class RedisRateLimiter:
    mode = "redis"

    def __init__(self, redis_url: str, prefix: str = "mcp_guard:rate") -> None:
        try:
            import redis
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise RuntimeError("Redis rate limiting requires optional redis dependency") from exc
        self._client = redis.Redis.from_url(redis_url, decode_responses=True)
        self._prefix = prefix

    def allow(self, key: str, limit: int, window_seconds: int) -> bool:
        bucket = int(time.time() // window_seconds)
        redis_key = f"{self._prefix}:{key}:{bucket}"
        pipe = self._client.pipeline()
        pipe.incr(redis_key)
        pipe.expire(redis_key, window_seconds * 2)
        count, _ = pipe.execute()
        return int(count) <= limit


def build_rate_limiter() -> RateLimiter:
    redis_url = os.getenv("MCP_GUARD_REDIS_URL", "")
    if not redis_url:
        return LocalRateLimiter()
    try:
        return RedisRateLimiter(redis_url)
    except RuntimeError:
        if os.getenv("MCP_GUARD_REDIS_REQUIRED", "").lower() in {"1", "true", "yes"}:
            raise
        return LocalRateLimiter(mode="local-fallback")
