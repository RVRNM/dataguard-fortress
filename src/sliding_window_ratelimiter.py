"""Sliding-window rate limiter with pluggable backends (memory, redis).

Provides an alternative to token-bucket for use-cards that need strict
per-window rate limits (e.g., "max 100 requests per 60 seconds").
"""

from __future__ import annotations

import asyncio
import logging
import time
from abc import ABC, abstractmethod
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Backends
# ---------------------------------------------------------------------------


class RateLimiterBackend(ABC):
    """Abstract backend for sliding-window rate limiter state storage."""

    @abstractmethod
    async def add_timestamp(self, key: str, ts: float, window: float) -> None:
        """Record a request timestamp for *key* within *window* seconds."""

    @abstractmethod
    async def count_recent(self, key: str, window: float, now: float) -> int:
        """Count requests for *key* within the last *window* seconds from *now*."""

    @abstractmethod
    async def get_oldest(self, key: str) -> float | None:
        """Return the oldest active timestamp or None."""

    @abstractmethod
    async def clear(self, key: str) -> None:
        """Remove all state for *key*."""


class MemoryRateLimiterBackend(RateLimiterBackend):
    """In-memory list-based backend. Suitable for tests and single-instance."""

    def __init__(self) -> None:
        self._store: dict[str, list[float]] = {}
        self._lock = asyncio.Lock()

    async def add_timestamp(self, key: str, ts: float, window: float) -> None:
        async with self._lock:
            if key not in self._store:
                self._store[key] = []
            self._store[key].append(ts)
            # Prune old entries
            cutoff = ts - window
            self._store[key] = [t for t in self._store[key] if t > cutoff]

    async def count_recent(self, key: str, window: float, now: float) -> int:
        async with self._lock:
            entries = self._store.get(key, [])
            cutoff = now - window
            return sum(1 for t in entries if t > cutoff)

    async def get_oldest(self, key: str) -> float | None:
        async with self._lock:
            entries = self._store.get(key, [])
            return min(entries) if entries else None

    async def clear(self, key: str) -> None:
        async with self._lock:
            self._store.pop(key, None)

    def clear_all(self) -> None:
        self._store.clear()


class RedisRateLimiterBackend(RateLimiterBackend):
    """Redis-backed backend using sorted sets (ZADD/ZREMRANGEBYSCORE/ZCARD)."""

    def __init__(self, redis_client: Any) -> None:
        self._redis = redis_client
        self._counter = 0

    async def add_timestamp(self, key: str, ts: float, window: float) -> None:
        score = ts
        # Use a monotonic counter to generate unique members so that
        # multiple requests within the same clock tick don't overwrite.
        self._counter += 1
        member = f"{ts}:{self._counter}"
        pipe = self._redis.pipeline()
        pipe.zadd(key, {member: score})
        # Remove entries strictly outside the window (older than ts - window)
        # Use exclusive lower bound via "(" prefix to avoid removing entries
        # that are exactly at the boundary (which count_recent would include).
        min_score = ts - window
        pipe.zremrangebyscore(key, "-inf", f"({min_score}")
        await pipe.execute()

    async def count_recent(self, key: str, window: float, now: float) -> int:
        min_score = now - window
        return await self._redis.zcount(key, min_score, "+inf")  # type: ignore[no-any-return]

    async def get_oldest(self, key: str) -> float | None:
        results = await self._redis.zrange(key, 0, 0, withscores=True)
        if results:
            return results[0][1]
        return None

    async def clear(self, key: str) -> None:
        await self._redis.delete(key)


# ---------------------------------------------------------------------------
# Sliding-Window Rate Limiter
# ---------------------------------------------------------------------------


class SlidingWindowRateLimiter:
    """Sliding-window log rate limiter.

    Tracks individual request timestamps in a rolling window and rejects
    new requests when the count exceeds ``max_requests``.

    Args:
        backend: Storage backend (memory or redis).
        max_requests: Maximum number of requests allowed per window.
        window_seconds: Size of the rolling window in seconds.
    """

    def __init__(
        self,
        backend: RateLimiterBackend,
        max_requests: int = 100,
        window_seconds: float = 60.0,
    ) -> None:
        if max_requests < 1:
            raise ValueError("max_requests must be >= 1")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")

        self._backend = backend
        self._max_requests = max_requests
        self._window_seconds = window_seconds

    @property
    def max_requests(self) -> int:
        return self._max_requests

    @property
    def window_seconds(self) -> float:
        return self._window_seconds

    async def check(self, key: str) -> tuple[bool, dict]:
        """Check if a new request for *key* is allowed.

        Returns:
            Tuple of (allowed: bool, info: dict).
            *info* contains ``remaining``, ``limit``, ``reset_at``, and
            ``current_count``.
        """
        now = time.monotonic()
        count = await self._backend.count_recent(key, self._window_seconds, now)

        allowed = count < self._max_requests

        # Compute reset info
        oldest = await self._backend.get_oldest(key)
        reset_at = oldest + self._window_seconds if oldest is not None else now + self._window_seconds

        remaining = max(0, self._max_requests - count)
        return allowed, {
            "allowed": allowed,
            "remaining": remaining,
            "limit": self._max_requests,
            "current_count": count,
            "reset_at": reset_at,
        }

    async def record(self, key: str) -> tuple[bool, dict]:
        """Record a request for *key* and check if it's allowed.

        Unlike :meth:`check`, this increments the counter.  Returns the
        same tuple format.
        """
        now = time.monotonic()
        # Record first, then count
        await self._backend.add_timestamp(key, ts=now, window=self._window_seconds)
        count = await self._backend.count_recent(key, self._window_seconds, now)

        allowed = count <= self._max_requests

        oldest = await self._backend.get_oldest(key)
        reset_at = oldest + self._window_seconds if oldest is not None else now + self._window_seconds

        remaining = max(0, self._max_requests - count)
        return allowed, {
            "allowed": allowed,
            "remaining": remaining,
            "limit": self._max_requests,
            "current_count": count,
            "reset_at": reset_at,
        }

    async def remaining(self, key: str) -> int:
        """Return remaining quota for *key* without recording a request."""
        now = time.monotonic()
        count = await self._backend.count_recent(key, self._window_seconds, now)
        return max(0, self._max_requests - count)

    async def reset(self, key: str) -> None:
        """Clear all recorded timestamps for *key*."""
        await self._backend.clear(key)
