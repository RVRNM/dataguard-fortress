import pytest

from src.token_bucket import TokenBucket


class TestRedisBucket:
    """Tests for Redis-backed token bucket."""

    @pytest.mark.asyncio
    async def test_redis_bucket_state_fields(self, redis_bucket: TokenBucket) -> None:
        """State stored in Redis has expected fields."""
        await redis_bucket.try_acquire(2)
        state = await redis_bucket.current_state()
        # After acquiring 2 from capacity 5, we should have ~3 tokens.
        # current_state() refills based on elapsed time, so allow up to capacity (5.0).
        assert 2.9 <= state.tokens <= 5.0
        assert state.max_tokens == pytest.approx(5.0, abs=0.1)
        assert state.refill_rate == 10.0
        assert state.last_refill > 0
