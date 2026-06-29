"""Token-bucket rate limiter with pluggable backends (memory, redis).

Provides:
  - TokenBucket: core algorithm with configurable rate/capacity
  - MemoryTokenBucketBackend: in-memory dict backend (default)
  - RedisTokenBucketBackend: Redis-backed shared state
  - acquire / try_acquire / expire / blocking semantics
  - Per-tenant isolation via key prefixes
"""

from __future__ import annotations

import asyncio
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Backends
# ---------------------------------------------------------------------------


class TokenBucketBackend(ABC):
    """Abstract backend for token-bucket state storage."""

    @abstractmethod
    async def get_state(self, key: str) -> dict | None:
        """Return stored state dict or None if key doesn't exist."""

    @abstractmethod
    async def set_state(self, key: str, state: dict, ttl: float | None = None) -> None:
        """Persist state dict for key."""

    @abstractmethod
    async def delete(self, key: str) -> None:
        """Remove key from backend."""


class MemoryTokenBucketBackend(TokenBucketBackend):
    """In-memory dict-based backend. Suitable for single-instance deployments."""

    def __init__(self) -> None:
        self._store: dict[str, dict] = {}
        self._expiry: dict[str, float] = {}
        self._lock = asyncio.Lock()

    async def get_state(self, key: str) -> dict | None:
        async with self._lock:
            # Check expiry
            if key in self._expiry and time.monotonic() > self._expiry[key]:
                self._store.pop(key, None)
                self._expiry.pop(key, None)
                return None
            state = self._store.get(key)
            return state.copy() if state is not None else None

    async def set_state(self, key: str, state: dict, ttl: float | None = None) -> None:
        async with self._lock:
            self._store[key] = state.copy()
            if ttl is not None:
                self._expiry[key] = time.monotonic() + ttl
            else:
                self._expiry.pop(key, None)

    async def delete(self, key: str) -> None:
        async with self._lock:
            self._store.pop(key, None)
            self._expiry.pop(key, None)

    def clear(self) -> None:
        """Clear all state (test helper)."""
        self._store.clear()
        self._expiry.clear()


class RedisTokenBucketBackend(TokenBucketBackend):
    """Redis-backed state using atomic HSET/HGET/EXPIRE commands."""

    def __init__(self, redis_client: Any) -> None:
        self._redis = redis_client

    async def get_state(self, key: str) -> dict | None:
        import json

        data = await self._redis.get(key)
        if data is None:
            return None
        if isinstance(data, bytes):
            data = data.decode("utf-8")
        return json.loads(data)

    async def set_state(self, key: str, state: dict, ttl: float | None = None) -> None:
        import json

        raw = json.dumps(state)
        if ttl is not None:
            await self._redis.set(key, raw, ex=int(ttl))
        else:
            await self._redis.set(key, raw)

    async def delete(self, key: str) -> None:
        await self._redis.delete(key)


# ---------------------------------------------------------------------------
# Token Bucket
# ---------------------------------------------------------------------------


@dataclass
class TokenBucketState:
    """Mutable state of a token bucket."""

    tokens: float
    last_refill: float
    max_tokens: float
    refill_rate: float  # tokens per second


class TokenBucket:
    """Token-bucket rate limiter algorithm.

    Each bucket is identified by a key (typically tenant-specific).
    Tokens are refilled continuously at ``refill_rate`` per second up
    to ``max_tokens`` (the burst capacity).

    Args:
        backend: Storage backend (memory or redis).
        key: Unique bucket identifier.
        rate: Token refill rate (tokens/second).
        capacity: Maximum burst (bucket capacity).
        ttl: Seconds after which idle buckets expire (None = never).
    """

    def __init__(
        self,
        backend: TokenBucketBackend,
        key: str,
        rate: float,
        capacity: int,
        ttl: float | None = 3600.0,
    ) -> None:
        if rate <= 0:
            raise ValueError("rate must be positive")
        if capacity < 1:
            raise ValueError("capacity must be >= 1")

        self._backend = backend
        self._key = key
        self._rate = rate
        self._capacity = capacity
        self._ttl = ttl

    # ------------------------------------------------------------------
    # Core operations
    # ------------------------------------------------------------------

    async def _load_state(self) -> TokenBucketState:
        """Load state from backend, or seed a fresh bucket."""
        raw = await self._backend.get_state(self._key)
        if raw is not None:
            return TokenBucketState(
                tokens=float(raw["tokens"]),
                last_refill=float(raw["last_refill"]),
                max_tokens=float(raw["max_tokens"]),
                refill_rate=float(raw["refill_rate"]),
            )
        now = time.monotonic()
        return TokenBucketState(
            tokens=float(self._capacity),
            last_refill=now,
            max_tokens=float(self._capacity),
            refill_rate=self._rate,
        )

    async def _save_state(self, state: TokenBucketState) -> None:
        await self._backend.set_state(
            self._key,
            {
                "tokens": state.tokens,
                "last_refill": state.last_refill,
                "max_tokens": state.max_tokens,
                "refill_rate": state.refill_rate,
            },
            ttl=self._ttl,
        )

    def _refill(self, state: TokenBucketState, now: float) -> None:
        elapsed = now - state.last_refill
        if elapsed > 0:
            added = elapsed * state.refill_rate
            state.tokens = min(state.max_tokens, state.tokens + added)
            state.last_refill = now

    async def try_acquire(self, tokens: int = 1) -> bool:
        """Attempt to consume *tokens* without blocking.

        Returns True if tokens were available and consumed, False otherwise.
        """
        if tokens <= 0:
            return True

        state = await self._load_state()
        now = time.monotonic()
        self._refill(state, now)

        if state.tokens >= tokens:
            state.tokens -= tokens
            await self._save_state(state)
            return True
        else:
            await self._save_state(state)
            return False

    async def acquire(self, tokens: int = 1, timeout: float = 30.0) -> bool:
        """Acquire *tokens*, blocking until available or *timeout* expires.

        Returns True if acquired, False if timeout exceeded.
        """
        if tokens <= 0:
            return True

        deadline = time.monotonic() + timeout
        # Exponential backoff starting at 10 ms
        backoff = 0.01

        while True:
            if await self.try_acquire(tokens):
                return True

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False

            wait = min(backoff, remaining)
            await asyncio.sleep(wait)
            backoff = min(backoff * 2, 1.0)  # cap at 1s

    async def current_state(self) -> TokenBucketState:
        """Return the current (refilled) bucket state without modifying it."""
        state = await self._load_state()
        self._refill(state, time.monotonic())
        return state

    async def available_tokens(self) -> float:
        """Return how many tokens are currently available."""
        state = await self.current_state()
        return state.tokens

    async def reset(self) -> None:
        """Delete all state for this bucket."""
        await self._backend.delete(self._key)


# ---------------------------------------------------------------------------
# Per-tenant bucket factory
# ---------------------------------------------------------------------------


class TenantTokenBuckets:
    """Factory that creates per-tenant TokenBuckets sharing one backend."""

    def __init__(
        self,
        backend: TokenBucketBackend,
        rate: float = 10.0,
        capacity: int = 50,
        ttl: float | None = 3600.0,
    ) -> None:
        self._backend = backend
        self._rate = rate
        self._capacity = capacity
        self._ttl = ttl
        self._buckets: dict[str, TokenBucket] = {}

    def get_bucket(self, tenant_id: str) -> TokenBucket:
        if tenant_id not in self._buckets:
            self._buckets[tenant_id] = TokenBucket(
                backend=self._backend,
                key=f"tb:tenant:{tenant_id}",
                rate=self._rate,
                capacity=self._capacity,
                ttl=self._ttl,
            )
        return self._buckets[tenant_id]

    def clear(self) -> None:
        """Remove all cached bucket instances."""
        self._buckets.clear()
