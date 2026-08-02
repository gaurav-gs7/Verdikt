from __future__ import annotations

import dataclasses
import hashlib
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
        _validate_limit(limit, window_seconds)
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
    _INCREMENT_SCRIPT = """
local count = redis.call('INCR', KEYS[1])
if count == 1 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
end
return count
"""

    def __init__(self, redis_url: str, prefix: str = "judikt:rate") -> None:
        try:
            import redis
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise RuntimeError("Redis rate limiting requires optional redis dependency") from exc
        self._client = redis.Redis.from_url(redis_url, decode_responses=True)
        self._prefix = prefix
        try:
            self._client.ping()
        except redis.RedisError as exc:
            raise RuntimeError("Redis rate limiting backend is unavailable") from exc

    def allow(self, key: str, limit: int, window_seconds: int) -> bool:
        _validate_limit(limit, window_seconds)
        key_digest = hashlib.sha256(key.encode()).hexdigest()
        redis_key = f"{self._prefix}:{key_digest}"
        count = self._client.eval(
            self._INCREMENT_SCRIPT,
            1,
            redis_key,
            window_seconds * 1000,
        )
        return int(count) <= limit


def build_rate_limiter() -> RateLimiter:
    redis_url = os.getenv("JUDIKT_REDIS_URL", "")
    if not redis_url:
        return LocalRateLimiter()
    try:
        return RedisRateLimiter(redis_url)
    except RuntimeError:
        if os.getenv("JUDIKT_REDIS_REQUIRED", "").lower() in {"1", "true", "yes"}:
            raise
        return LocalRateLimiter(mode="local-fallback")


def _validate_limit(limit: int, window_seconds: int) -> None:
    if limit < 0:
        raise ValueError("rate limit must be zero or greater")
    if window_seconds <= 0:
        raise ValueError("rate-limit window must be greater than zero")
