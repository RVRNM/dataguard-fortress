"""Tests for the v03 modules: TokenBucket, TenantManager, DataClassifier,
and SlidingWindowRateLimiter.

All tests use in-memory backends or fakeredis — no real Redis required.
"""

from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

import pytest
import pytest_asyncio

# Ensure project root is importable
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.token_bucket import (
    MemoryTokenBucketBackend,
    RedisTokenBucketBackend,
    TenantTokenBuckets,
    TokenBucket,
)
from src.tenant import DEFAULT_TENANT, TenantConfig, TenantManager
from src.classifier import ClassificationResult, DataClassifier, SensitivityLevel
from src.sliding_window_ratelimiter import (
    MemoryRateLimiterBackend,
    RedisRateLimiterBackend,
    SlidingWindowRateLimiter,
)


# ════════════════════════════════════════════════════════════════════════════════
# TestTokenBucket
# ════════════════════════════════════════════════════════════════════════════════


class TestTokenBucket:
    """TokenBucket: memory backend, acquire/expire/blocking, per-tenant isolation."""

    @pytest.fixture
    def backend(self) -> MemoryTokenBucketBackend:
        return MemoryTokenBucketBackend()

    @pytest.fixture
    def bucket(self, backend: MemoryTokenBucketBackend) -> TokenBucket:
        return TokenBucket(
            backend=backend,
            key="test:bucket:basic",
            rate=10.0,
            capacity=20,
            ttl=3600.0,
        )

    # ------------------------------------------------------------------
    # Initialization
    # ------------------------------------------------------------------

    def test_init_invalid_rate(self, backend: MemoryTokenBucketBackend) -> None:
        """rate <= 0 raises ValueError."""
        with pytest.raises(ValueError, match="rate must be positive"):
            TokenBucket(backend=backend, key="x", rate=0, capacity=10)

    def test_init_invalid_capacity(self, backend: MemoryTokenBucketBackend) -> None:
        """capacity < 1 raises ValueError."""
        with pytest.raises(ValueError, match="capacity must be >= 1"):
            TokenBucket(backend=backend, key="x", rate=10, capacity=0)

    def test_init_negative_rate(self, backend: MemoryTokenBucketBackend) -> None:
        """Negative rate raises ValueError."""
        with pytest.raises(ValueError, match="rate must be positive"):
            TokenBucket(backend=backend, key="x", rate=-5, capacity=10)

    # ------------------------------------------------------------------
    # try_acquire (non-blocking)
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_try_acquire_initial_success(
        self, bucket: TokenBucket
    ) -> None:
        """First acquire on a fresh bucket should succeed."""
        result = await bucket.try_acquire(1)
        assert result is True

    @pytest.mark.asyncio
    async def test_try_acquire_drains_tokens(
        self, bucket: TokenBucket
    ) -> None:
        """Multiple acquires consume tokens."""
        for _ in range(10):
            assert await bucket.try_acquire(1) is True
        # 10 of 20 used → 10 remaining
        assert await bucket.available_tokens() == 10.0

    @pytest.mark.asyncio
    async def test_try_acquire_fails_when_empty(
        self, bucket: TokenBucket
    ) -> None:
        """When no tokens remain, try_acquire returns False."""
        # Drain all 20 tokens
        for _ in range(20):
            assert await bucket.try_acquire(1) is True
        # Next one should fail
        result = await bucket.try_acquire(1)
        assert result is False

    @pytest.mark.asyncio
    async def test_try_acquire_returns_false_not_exception(
        self, bucket: TokenBucket
    ) -> None:
        """Exceeding capacity returns False, not an exception."""
        for _ in range(20):
            await bucket.try_acquire(1)
        # Should not raise, just return False
        assert await bucket.try_acquire(5) is False

    @pytest.mark.asyncio
    async def test_try_acquire_zero_tokens_always_succeeds(
        self, bucket: TokenBucket
    ) -> None:
        """Requesting 0 tokens always succeeds (including on empty bucket)."""
        # Drain bucket
        for _ in range(20):
            await bucket.try_acquire(1)
        assert await bucket.try_acquire(0) is True

    @pytest.mark.asyncio
    async def test_try_acquire_large_burst(
        self, bucket: TokenBucket
    ) -> None:
        """Acquiring more than available in one call returns False."""
        # Capacity is 20, try to take 21
        assert await bucket.try_acquire(21) is False
        # Bucket state should be untouched
        assert await bucket.available_tokens() == 20.0

    @pytest.mark.asyncio
    async def test_try_acquire_exact_capacity(
        self, bucket: TokenBucket
    ) -> None:
        """Acquiring exactly the capacity succeeds."""
        assert await bucket.try_acquire(20) is True
        assert await bucket.available_tokens() == 0.0

    # ------------------------------------------------------------------
    # Refill behaviour
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_tokens_refill_over_time(self) -> None:
        """Tokens refill at the configured rate."""
        backend = MemoryTokenBucketBackend()
        bucket = TokenBucket(
            backend=backend,
            key="test:refill",
            rate=100.0,
            capacity=10,
            ttl=3600.0,
        )
        # Drain all
        for _ in range(10):
            await bucket.try_acquire(1)
        assert await bucket.available_tokens() == 0.0

        # Wait for refill
        await asyncio.sleep(0.3)
        available = await bucket.available_tokens()
        # At 100/s, after 0.3s we should have ~30, capped at 10
        assert available == pytest.approx(10.0, abs=1.0)

    @pytest.mark.asyncio
    async def test_refill_does_not_exceed_capacity(self) -> None:
        """Refill respects the capacity cap."""
        backend = MemoryTokenBucketBackend()
        bucket = TokenBucket(
            backend=backend,
            key="test:cap",
            rate=1000.0,
            capacity=5,
            ttl=3600.0,
        )
        await bucket.try_acquire(3)
        await bucket.try_acquire(2)  # drain to 0
        assert await bucket.available_tokens() == 0.0
        await asyncio.sleep(0.1)
        assert await bucket.available_tokens() <= 5.0

    # ------------------------------------------------------------------
    # Blocking acquire
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_acquire_blocks_until_available(self) -> None:
        """acquire() blocks until tokens refill."""
        backend = MemoryTokenBucketBackend()
        bucket = TokenBucket(
            backend=backend,
            key="test:block",
            rate=50.0,  # 50 tokens/sec refill
            capacity=5,
            ttl=3600.0,
        )
        # Drain capacity
        for _ in range(5):
            await bucket.try_acquire(1)

        # This should block briefly then succeed
        start = time.monotonic()
        result = await bucket.acquire(1, timeout=2.0)
        elapsed = time.monotonic() - start

        assert result is True
        assert elapsed >= 0.01  # actually waited at least a little

    @pytest.mark.asyncio
    async def test_acquire_timeout_returns_false(self) -> None:
        """acquire() returns False when timeout expires."""
        backend = MemoryTokenBucketBackend()
        bucket = TokenBucket(
            backend=backend,
            key="test:timeout",
            rate=1.0,  # very slow refill
            capacity=1,
            ttl=3600.0,
        )
        # Drain
        await bucket.try_acquire(1)

        # With rate=1/s and timeout=0.2s, should fail
        result = await bucket.acquire(1, timeout=0.2)
        assert result is False

    @pytest.mark.asyncio
    async def test_acquire_zero_tokens(self, backend: MemoryTokenBucketBackend) -> None:
        """acquire(0) returns immediately without blocking."""
        bucket = TokenBucket(backend, "test:zero", rate=1, capacity=5, ttl=3600)
        for _ in range(5):
            await bucket.try_acquire(1)
        assert await bucket.acquire(0) is True

    # ------------------------------------------------------------------
    # Per-tenant isolation
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_per_tenant_bucket_isolation(
        self, backend: MemoryTokenBucketBackend
    ) -> None:
        """Different buckets share a backend but don't share state."""
        bucket_a = TokenBucket(backend, "tenant:a", rate=10, capacity=10, ttl=3600)
        bucket_b = TokenBucket(backend, "tenant:b", rate=10, capacity=10, ttl=3600)

        # Drain tenant A
        for _ in range(10):
            await bucket_a.try_acquire(1)

        # Tenant B should still have full capacity
        assert await bucket_b.available_tokens() == 10.0
        assert await bucket_b.try_acquire(1) is True
        assert await bucket_a.try_acquire(1) is False  # A still empty

    @pytest.mark.asyncio
    async def test_tenant_token_buckets_factory(self) -> None:
        """TenantTokenBuckets returns isolated per-tenant buckets."""
        backend = MemoryTokenBucketBackend()
        factory = TenantTokenBuckets(backend, rate=10, capacity=10, ttl=3600)

        bucket_x = factory.get_bucket("tenant-x")
        bucket_y = factory.get_bucket("tenant-y")

        # Same tenant returns same instance
        assert factory.get_bucket("tenant-x") is bucket_x

        # Drain x
        for _ in range(10):
            await bucket_x.try_acquire(1)

        assert await bucket_x.available_tokens() == 0.0
        assert await bucket_y.available_tokens() == 10.0

    @pytest.mark.asyncio
    async def test_same_key_same_state(
        self, backend: MemoryTokenBucketBackend
    ) -> None:
        """Two TokenBuckets with the same key share state."""
        b1 = TokenBucket(backend, "shared:key", rate=10, capacity=10, ttl=3600)
        b2 = TokenBucket(backend, "shared:key", rate=10, capacity=10, ttl=3600)

        await b1.try_acquire(5)
        # b2 should see the reduced state
        assert await b2.available_tokens() == 5.0

    # ------------------------------------------------------------------
    # Expiry
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_bucket_expires_after_ttl(self) -> None:
        """Backend state expires after TTL."""
        backend = MemoryTokenBucketBackend()
        bucket = TokenBucket(
            backend=backend,
            key="test:expire",
            rate=10,
            capacity=5,
            ttl=0.2,  # 200ms expiry
        )
        await bucket.try_acquire(3)
        assert await bucket.available_tokens() == 2.0

        # Wait for expiry
        await asyncio.sleep(0.3)
        # After expiry, state should be fresh again
        assert await bucket.available_tokens() == 5.0

    @pytest.mark.asyncio
    async def test_reset_clears_state(self, bucket: TokenBucket) -> None:
        """reset() clears bucket state."""
        await bucket.try_acquire(10)
        assert await bucket.available_tokens() == 10.0
        await bucket.reset()
        # After reset, fresh state = full capacity
        assert await bucket.available_tokens() == 20.0

    @pytest.mark.asyncio
    async def test_backend_delete_clears_state(
        self, backend: MemoryTokenBucketBackend
    ) -> None:
        """Deleting from backend removes state entirely."""
        bucket = TokenBucket(backend, "del:key", rate=10, capacity=5, ttl=3600)
        await bucket.try_acquire(5)
        await backend.delete("del:key")
        assert await bucket.available_tokens() == 5.0

    # ------------------------------------------------------------------
    # Current state inspection
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_current_state_refills(self) -> None:
        """current_state() returns a refilled view without consuming."""
        backend = MemoryTokenBucketBackend()
        bucket = TokenBucket(backend, "state:key", rate=10, capacity=5, ttl=3600)
        await bucket.try_acquire(5)
        assert await bucket.available_tokens() == 0.0

        await asyncio.sleep(0.2)
        state = await bucket.current_state()
        # Should show ~2 tokens (10/s * 0.2s = 2)
        assert state.tokens == pytest.approx(2.0, abs=1.0)
        assert state.max_tokens == 5.0
        assert state.refill_rate == 10.0


# ════════════════════════════════════════════════════════════════════════════════
# TestTenantManager
# ════════════════════════════════════════════════════════════════════════════════


class TestTenantManager:
    """TenantManager: load from dir, reload, default fallback."""

    @pytest.fixture
    def tenants_dir(self, tmp_path: Path) -> Path:
        """Create a temp directory for tenant YAML files."""
        return tmp_path / "tenants"

    @pytest.fixture
    def manager(self, tenants_dir: Path) -> TenantManager:
        """Create a TenantManager pointing at our temp dir."""
        return TenantManager(tenants_dir, scan_interval=60.0)

    # ------------------------------------------------------------------
    # Loading from directory
    # ------------------------------------------------------------------

    def test_load_from_dir_empty(
        self, tenants_dir: Path, manager: TenantManager
    ) -> None:
        """Empty directory: no tenants loaded."""
        assert manager.list_tenants() == []
        assert len(manager) == 0

    def test_load_from_dir_single_tenant(self, manager: TenantManager) -> None:
        """Loading a single YAML file creates one tenant."""
        # Write a tenant file via the manager's dir
        cfg_data = {
            "tenant_id": "acme-corp",
            "name": "ACME Corporation",
            "description": "Test tenant",
            "enabled": True,
            "rate_limit": {
                "requests_per_second": 100.0,
                "burst_size": 50,
                "max_concurrent": 10,
            },
        }
        import yaml as _yaml

        with open(manager.tenants_dir / "acme-corp.yml", "w") as f:
            _yaml.dump(cfg_data, f)

        # Force reload to pick up the new file
        manager.reload()

        tenants = manager.list_tenants()
        assert tenants == ["acme-corp"]
        assert "acme-corp" in manager

        cfg = manager.get_tenant("acme-corp")
        assert cfg.tenant_id == "acme-corp"
        assert cfg.name == "ACME Corporation"
        assert cfg.rate_limit.requests_per_second == 100.0
        assert cfg.rate_limit.burst_size == 50

    def test_load_from_dir_multiple_tenants(
        self, manager: TenantManager
    ) -> None:
        """Multiple YAML files are all loaded."""
        import yaml as _yaml

        for tid in ("tenant-a", "tenant-b", "tenant-c"):
            data = {"tenant_id": tid, "enabled": True}
            with open(manager.tenants_dir / f"{tid}.yml", "w") as f:
                _yaml.dump(data, f)

        manager.reload()
        assert manager.list_tenants() == ["tenant-a", "tenant-b", "tenant-c"]

    def test_load_yaml_extension(self, manager: TenantManager) -> None:
        """Files with .yaml extension are also loaded."""
        import yaml as _yaml

        data = {"tenant_id": "yaml-tenant"}
        with open(manager.tenants_dir / "yaml-tenant.yaml", "w") as f:
            _yaml.dump(data, f)

        manager.reload()
        assert "yaml-tenant" in manager.list_tenants()

    def test_load_invalid_yaml_skipped(self, manager: TenantManager) -> None:
        """Invalid YAML files are skipped gracefully."""
        import yaml as _yaml

        # Write a valid and an invalid file
        with open(manager.tenants_dir / "valid.yml", "w") as f:
            _yaml.dump({"tenant_id": "valid"}, f)

        with open(manager.tenants_dir / "invalid.yml", "w") as f:
            f.write("{{{{{{\nthis: is: not: yaml: :::\n")

        manager.reload()
        # valid should load, invalid should be skipped
        assert "valid" in manager.list_tenants()
        assert "invalid" not in manager.list_tenants()

    def test_load_non_mapping_yaml_skipped(
        self, manager: TenantManager
    ) -> None:
        """YAML files that don't contain a mapping are skipped."""
        with open(manager.tenants_dir / "bad.yml", "w") as f:
            f.write("- item1\n- item2\n")

        manager.reload()
        assert "bad" not in manager.list_tenants()

    # ------------------------------------------------------------------
    # Default fallback
    # ------------------------------------------------------------------

    def test_default_fallback_for_unknown_tenant(
        self, manager: TenantManager
    ) -> None:
        """get_tenant() returns a default for unknown tenant IDs."""
        cfg = manager.get_tenant("nonexistent-tenant")
        # Returns default with tenant_id rewritten
        assert cfg.tenant_id == "nonexistent-tenant"
        assert cfg.enabled is True

    def test_default_fallback_has_reasonable_values(
        self, manager: TenantManager
    ) -> None:
        """Default tenant has reasonable rate-limit values."""
        cfg = manager.get_tenant("missing")
        assert cfg.rate_limit.requests_per_second == DEFAULT_TENANT.rate_limit.requests_per_second
        assert cfg.rate_limit.burst_size == DEFAULT_TENANT.rate_limit.burst_size

    def test_default_fallback_custom_instance(
        self, tenants_dir: Path
    ) -> None:
        """A custom default tenant can be provided."""
        from src.tenant import TenantRateLimit as TRateLimit

        custom_default = TenantConfig(
            tenant_id="fallback",
            rate_limit=TRateLimit(
                requests_per_second=1.0,
                burst_size=2,
                max_concurrent=1,
                window_seconds=30,
            ),
        )
        mgr = TenantManager(tenants_dir, default_tenant=custom_default)
        cfg = mgr.get_tenant("unknown")
        # tenant_id is rewritten to the requested id
        assert cfg.tenant_id == "unknown"

    # ------------------------------------------------------------------
    # Reload
    # ------------------------------------------------------------------

    def test_reload_adds_new_tenants(self, manager: TenantManager) -> None:
        """Reload picks up newly added files."""
        import yaml as _yaml

        # Initially empty
        assert manager.list_tenants() == []

        # Add a file
        with open(manager.tenants_dir / "new-tenant.yml", "w") as f:
            _yaml.dump({"tenant_id": "new-tenant"}, f)

        manager.reload()
        assert "new-tenant" in manager.list_tenants()

    def test_reload_removes_deleted_tenants(self, manager: TenantManager) -> None:
        """Reload removes tenants whose files were deleted."""
        import yaml as _yaml
        import os

        fpath = manager.tenants_dir / "temp-tenant.yml"
        with open(fpath, "w") as f:
            _yaml.dump({"tenant_id": "temp-tenant"}, f)

        manager.reload()
        assert "temp-tenant" in manager.list_tenants()

        # Delete the file
        os.remove(fpath)
        manager.reload()
        assert "temp-tenant" not in manager.list_tenants()

    def test_reload_updates_changed_files(self, manager: TenantManager) -> None:
        """Reload picks up changes made to existing files."""
        import yaml as _yaml

        fpath = manager.tenants_dir / "mutable.yml"
        with open(fpath, "w") as f:
            _yaml.dump({"tenant_id": "mutable", "name": "Original"}, f)

        manager.reload()
        cfg = manager.get_tenant("mutable")
        assert cfg.name == "Original"

        # Small delay to ensure mtime changes
        time.sleep(0.05)
        with open(fpath, "w") as f:
            _yaml.dump({"tenant_id": "mutable", "name": "Updated"}, f)

        manager.reload()
        cfg = manager.get_tenant("mutable")
        assert cfg.name == "Updated"

    def test_reload_skips_unchanged_files(self, manager: TenantManager) -> None:
        """Reload with same mtime doesn't re-parse."""
        import yaml as _yaml

        fpath = manager.tenants_dir / "stable.yml"
        with open(fpath, "w") as f:
            _yaml.dump({"tenant_id": "stable", "name": "v1"}, f)

        manager.reload()

        # Reload again without change
        manager.reload()
        cfg = manager.get_tenant("stable")
        assert cfg.name == "v1"

    # ------------------------------------------------------------------
    # Async watcher
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_watcher_starts_and_stops(
        self, tenants_dir: Path
    ) -> None:
        """Watcher start/stop lifecycle works."""
        mgr = TenantManager(tenants_dir, scan_interval=1.0)
        assert mgr.is_watching is False

        await mgr.start()
        assert mgr.is_watching is True

        await mgr.stop()
        assert mgr.is_watching is False

    @pytest.mark.asyncio
    async def test_context_manager(self, tenants_dir: Path) -> None:
        """Async context manager works."""
        mgr = TenantManager(tenants_dir, scan_interval=1.0)

        async with mgr:
            assert mgr.is_watching is True

        assert mgr.is_watching is False

    @pytest.mark.asyncio
    async def test_watcher_periodically_reloads(
        self, tenants_dir: Path
    ) -> None:
        """Watcher reloads tenants at the configured interval."""
        import yaml as _yaml

        mgr = TenantManager(tenants_dir, scan_interval=0.2)
        await mgr.start()

        try:
            # Initially empty
            assert manager_list_no_conflict(mgr) == []

            # Add a file while watching
            with open(tenants_dir / "late-arrival.yml", "w") as f:
                _yaml.dump({"tenant_id": "late-arrival"}, f)

            # Wait for watcher to pick it up
            await asyncio.sleep(0.4)
            assert "late-arrival" in mgr.list_tenants()
        finally:
            await mgr.stop()


def manager_list_no_conflict(mgr: TenantManager) -> list:
    """Helper to call list_tenants outside the async context."""
    return mgr.list_tenants()


# ════════════════════════════════════════════════════════════════════════════════
# TestDataClassifier
# ════════════════════════════════════════════════════════════════════════════════


class TestDataClassifier:
    """DataClassifier: level classification, PII density, sync version."""

    @pytest.fixture
    def classifier(self) -> DataClassifier:
        return DataClassifier(pii_density_threshold=0.1)

    # ------------------------------------------------------------------
    # Level classification
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_public_text(self, classifier: DataClassifier) -> None:
        """Normal everyday text classified as PUBLIC."""
        result = await classifier.classify("What is the weather today?")
        assert result.level == SensitivityLevel.PUBLIC

    @pytest.mark.asyncio
    async def test_internal_keywords(self, classifier: DataClassifier) -> None:
        """Internal business terms classified as INTERNAL."""
        result = await classifier.classify("The quarterly report shows employee payroll data")
        assert result.level == SensitivityLevel.INTERNAL

    @pytest.mark.asyncio
    async def test_confidential_keywords(self, classifier: DataClassifier) -> None:
        """Confidential terms classified as CONFIDENTIAL."""
        result = await classifier.classify("The api_key is exposed in the log")
        assert result.level == SensitivityLevel.CONFIDENTIAL

    @pytest.mark.asyncio
    async def test_restricted_keywords(self, classifier: DataClassifier) -> None:
        """Restricted terms classified as RESTRICTED."""
        result = await classifier.classify("This contains classified information")
        assert result.level == SensitivityLevel.RESTRICTED

    @pytest.mark.asyncio
    async def test_social_security_keyword(self, classifier: DataClassifier) -> None:
        """SSN keyword triggers RESTRICTED."""
        result = await classifier.classify("Patient SSN is on file")
        assert result.level == SensitivityLevel.RESTRICTED

    @pytest.mark.asyncio
    async def test_credit_card_keyword(self, classifier: DataClassifier) -> None:
        """Credit card keyword triggers RESTRICTED."""
        result = await classifier.classify("The credit_card number was stolen")
        assert result.level == SensitivityLevel.RESTRICTED

    @pytest.mark.asyncio
    async def test_empty_text_is_public(self, classifier: DataClassifier) -> None:
        """Empty text classified as PUBLIC."""
        result = await classifier.classify("")
        assert result.level == SensitivityLevel.PUBLIC
        assert result.score == 0.0

    @pytest.mark.asyncio
    async def test_level_name_property(self, classifier: DataClassifier) -> None:
        """level_name returns the enum name string."""
        result = await classifier.classify("hello")
        assert result.level_name == "PUBLIC"

    # ------------------------------------------------------------------
    # PII density
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_pii_density_zero_for_clean_text(self) -> None:
        """Clean text has zero PII density."""
        cls = DataClassifier()
        # No PII patterns match → density 0
        result = await cls.classify("The weather is nice today")
        assert result.pii_density == 0.0

    @pytest.mark.asyncio
    async def test_pii_density_with_email(self) -> None:
        """Email address contributes to PII density."""
        cls = DataClassifier()
        result = await cls.classify("Contact user@example.com for details")
        # 1 PII match / ~5 words = 0.2
        assert result.pii_density > 0.0

    @pytest.mark.asyncio
    async def test_pii_density_clamps_to_restricted(self) -> None:
        """High PII density clamps classification to RESTRICTED."""
        cls = DataClassifier(pii_density_threshold=0.05)  # low threshold
        # Many PII matches in a short text
        text = (
            "emails: a@b.com c@d.com e@f.com "
            "phones: 555-111-2222 555-333-4444 "
            "ssn: 123-45-6789"
        )
        result = await cls.classify(text)
        # Should be RESTRICTED due to high density
        assert result.level == SensitivityLevel.RESTRICTED

    @pytest.mark.asyncio
    async def test_pii_density_with_ssn_only(self) -> None:
        """SSN alone is enough to add to density."""
        cls = DataClassifier(pii_density_threshold=0.01)
        result = await cls.classify("SSN 123-45-6789")
        assert result.pii_density > 0.0

    # ------------------------------------------------------------------
    # Score computation
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_score_is_between_0_and_1(self, classifier: DataClassifier) -> None:
        """Composite score is always between 0 and 1."""
        for text in [
            "hello",
            "api_key secret",
            "classified top_secret",
            "SSN 123-45-6789",
        ]:
            result = await classifier.classify(text)
            assert 0.0 <= result.score <= 1.0, f"Score {result.score} out of range for: {text}"

    @pytest.mark.asyncio
    async def test_reasons_populated(self, classifier: DataClassifier) -> None:
        """Classification result includes reason strings."""
        result = await classifier.classify("api_key is secret")
        assert len(result.reasons) > 0

    @pytest.mark.asyncio
    async def test_no_sensitive_indicator_reason(self, classifier: DataClassifier) -> None:
        """Public text gets 'no_sensitive_indicators' reason."""
        result = await classifier.classify("hello world")
        assert "no_sensitive_indicators" in result.reasons

    # ------------------------------------------------------------------
    # Sync version
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_classify_sync_returns_same_result(self) -> None:
        """classify_sync() returns the same result as async classify."""
        cls = DataClassifier()
        sync_result = cls.classify_sync("api_key is exposed")
        async_result = await cls.classify("api_key is exposed")
        assert sync_result.level == async_result.level
        assert sync_result.score == async_result.score
        assert sync_result.pii_density == async_result.pii_density

    def test_classify_sync_is_actually_sync(self, classifier: DataClassifier) -> None:
        """classify_sync() is a synchronous method."""
        result = classifier.classify_sync("classified info")
        assert isinstance(result, ClassificationResult)
        assert result.level == SensitivityLevel.RESTRICTED

    @pytest.mark.asyncio
    async def test_large_text_offload(self) -> None:
        """Large text (>50k chars) is offloaded to executor."""
        cls = DataClassifier()
        # Create text > 50k chars
        text = "secret api_key " * 3000  # ~54k chars
        result = await cls.classify(text)
        assert result.level == SensitivityLevel.CONFIDENTIAL

    # ------------------------------------------------------------------
    # Edge cases
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_case_insensitive_keywords(self, classifier: DataClassifier) -> None:
        """Keyword matching is case-insensitive."""
        r1 = await classifier.classify("API_KEY exposed")
        r2 = await classifier.classify("api_key exposed")
        assert r1.level == r2.level

    @pytest.mark.asyncio
    async def test_multiple_keyword_levels_wins_highest(
        self, classifier: DataClassifier
    ) -> None:
        """When multiple levels match, the highest wins."""
        # Has both internal ('employee') and confidential ('api_key')
        result = await classifier.classify("The employee leaked the api_key")
        assert result.level == SensitivityLevel.CONFIDENTIAL

    @pytest.mark.asyncio
    async def test_classification_result_dataclass(self) -> None:
        """ClassificationResult is a proper dataclass."""
        result = ClassificationResult(
            level=SensitivityLevel.PUBLIC,
            score=0.0,
            reasons=["test"],
            pii_density=0.0,
        )
        assert result.level == SensitivityLevel.PUBLIC
        assert result.score == 0.0


# ════════════════════════════════════════════════════════════════════════════════
# TestSlidingWindowRateLimiter
# ════════════════════════════════════════════════════════════════════════════════


class TestSlidingWindowRateLimiter:
    """SlidingWindowRateLimiter: memory backend + mocked redis."""

    # ------------------------------------------------------------------
    # Memory backend tests
    # ------------------------------------------------------------------

    @pytest.fixture
    def memory_backend(self) -> MemoryRateLimiterBackend:
        return MemoryRateLimiterBackend()

    @pytest.fixture
    def limiter(self, memory_backend: MemoryRateLimiterBackend) -> SlidingWindowRateLimiter:
        return SlidingWindowRateLimiter(
            backend=memory_backend,
            max_requests=5,
            window_seconds=1.0,
        )

    def test_init_invalid_max_requests(
        self, memory_backend: MemoryRateLimiterBackend
    ) -> None:
        """max_requests < 1 raises ValueError."""
        with pytest.raises(ValueError, match="max_requests must be >= 1"):
            SlidingWindowRateLimiter(memory_backend, max_requests=0, window_seconds=1.0)

    def test_init_invalid_window(
        self, memory_backend: MemoryRateLimiterBackend
    ) -> None:
        """window_seconds <= 0 raises ValueError."""
        with pytest.raises(ValueError, match="window_seconds must be positive"):
            SlidingWindowRateLimiter(memory_backend, max_requests=10, window_seconds=0)

    def test_init_negative_window(
        self, memory_backend: MemoryRateLimiterBackend
    ) -> None:
        """Negative window_seconds raises ValueError."""
        with pytest.raises(ValueError, match="window_seconds must be positive"):
            SlidingWindowRateLimiter(memory_backend, max_requests=10, window_seconds=-5)

    @pytest.mark.asyncio
    async def test_first_request_allowed(
        self, limiter: SlidingWindowRateLimiter
    ) -> None:
        """First request is always allowed."""
        allowed, info = await limiter.record("user1")
        assert allowed is True
        assert info["current_count"] == 1
        assert info["remaining"] == 4

    @pytest.mark.asyncio
    async def test_up_to_limit_allowed(
        self, limiter: SlidingWindowRateLimiter
    ) -> None:
        """All requests up to max_requests are allowed."""
        for i in range(5):
            allowed, info = await limiter.record("user1")
            assert allowed is True, f"Request {i+1} should be allowed"
            assert info["current_count"] == i + 1

    @pytest.mark.asyncio
    async def test_over_limit_rejected(
        self, limiter: SlidingWindowRateLimiter
    ) -> None:
        """Request beyond max_requests is rejected."""
        for _ in range(5):
            await limiter.record("user1")
        allowed, info = await limiter.record("user1")
        assert allowed is False
        assert info["remaining"] == 0
        assert info["current_count"] == 6

    @pytest.mark.asyncio
    async def test_remaining_decreases(
        self, limiter: SlidingWindowRateLimiter
    ) -> None:
        """remaining() decreases as requests are recorded."""
        assert await limiter.remaining("user1") == 5
        await limiter.record("user1")
        assert await limiter.remaining("user1") == 4
        await limiter.record("user1")
        assert await limiter.remaining("user1") == 3

    @pytest.mark.asyncio
    async def test_check_does_not_record(
        self, limiter: SlidingWindowRateLimiter
    ) -> None:
        """check() does NOT record a request."""
        for _ in range(10):
            allowed, info = await limiter.check("user1")
            assert allowed is True
            assert info["current_count"] == 0

    @pytest.mark.asyncio
    async def test_per_key_isolation(
        self, limiter: SlidingWindowRateLimiter
    ) -> None:
        """Different keys are tracked independently."""
        for _ in range(5):
            await limiter.record("user1")
        # user1 is now full
        allowed, _ = await limiter.record("user1")
        assert allowed is False

        # user2 should still be allowed
        allowed, info = await limiter.record("user2")
        assert allowed is True
        assert info["current_count"] == 1

    @pytest.mark.asyncio
    async def test_window_expires_old_entries(self) -> None:
        """Old entries outside the window are purged."""
        backend = MemoryRateLimiterBackend()
        limiter = SlidingWindowRateLimiter(
            backend=backend, max_requests=2, window_seconds=0.3
        )

        # Fill up
        await limiter.record("key")
        await limiter.record("key")
        allowed, _ = await limiter.record("key")
        assert allowed is False  # Full

        # Wait for window to expire
        await asyncio.sleep(0.4)

        # Old entries should have expired → new request allowed
        allowed, info = await limiter.record("key")
        assert allowed is True
        assert info["current_count"] == 1

    @pytest.mark.asyncio
    async def test_reset_clears_state(
        self, limiter: SlidingWindowRateLimiter
    ) -> None:
        """reset() clears all state for a key."""
        for _ in range(5):
            await limiter.record("user1")
        allowed, _ = await limiter.record("user1")
        assert allowed is False

        await limiter.reset("user1")
        allowed, info = await limiter.record("user1")
        assert allowed is True
        assert info["current_count"] == 1

    @pytest.mark.asyncio
    async def test_info_dict_has_reset_at(
        self, limiter: SlidingWindowRateLimiter
    ) -> None:
        """Info dict includes reset_at timestamp."""
        allowed, info = await limiter.record("user1")
        assert "reset_at" in info
        assert info["reset_at"] > time.monotonic()
        assert info["reset_at"] <= time.monotonic() + 1.0  # window is 1s

    @pytest.mark.asyncio
    async def test_info_dict_has_limit(
        self, limiter: SlidingWindowRateLimiter
    ) -> None:
        """Info dict includes the configured limit."""
        _, info = await limiter.record("user1")
        assert info["limit"] == 5

    # ------------------------------------------------------------------
    # MemoryRateLimiterBackend direct tests
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_memory_backend_add_and_count(self) -> None:
        """Backend stores and counts timestamps correctly."""
        backend = MemoryRateLimiterBackend()
        now = time.monotonic()
        await backend.add_timestamp("k", now, 10.0)
        await backend.add_timestamp("k", now + 0.1, 10.0)
        count = await backend.count_recent("k", 10.0, now + 0.2)
        assert count == 2

    @pytest.mark.asyncio
    async def test_memory_backend_prunes_old(self) -> None:
        """Backend prunes entries outside the window."""
        backend = MemoryRateLimiterBackend()
        now = time.monotonic()
        await backend.add_timestamp("k", now - 100, 10.0)  # very old
        await backend.add_timestamp("k", now, 10.0)  # recent
        count = await backend.count_recent("k", 10.0, now)
        assert count == 1

    @pytest.mark.asyncio
    async def test_memory_backend_get_oldest(self) -> None:
        """Returns oldest active timestamp."""
        backend = MemoryRateLimiterBackend()
        now = time.monotonic()
        await backend.add_timestamp("k", now, 10.0)
        await backend.add_timestamp("k", now + 5, 10.0)
        oldest = await backend.get_oldest("k")
        assert oldest is not None
        assert oldest == pytest.approx(now, abs=0.01)

    @pytest.mark.asyncio
    async def test_memory_backend_get_oldest_empty(self) -> None:
        """Returns None when no entries."""
        backend = MemoryRateLimiterBackend()
        result = await backend.get_oldest("nonexistent")
        assert result is None

    @pytest.mark.asyncio
    async def test_memory_backend_clear(self) -> None:
        """clear() removes all entries for a key."""
        backend = MemoryRateLimiterBackend()
        await backend.add_timestamp("k", time.monotonic(), 10.0)
        assert await backend.count_recent("k", 10.0, time.monotonic()) == 1
        await backend.clear("k")
        assert await backend.count_recent("k", 10.0, time.monotonic()) == 0

    @pytest.mark.asyncio
    async def test_memory_backend_clear_all(self) -> None:
        """clear_all() removes everything."""
        backend = MemoryRateLimiterBackend()
        await backend.add_timestamp("a", time.monotonic(), 10.0)
        await backend.add_timestamp("b", time.monotonic(), 10.0)
        backend.clear_all()
        assert backend._store == {}

    # ------------------------------------------------------------------
    # Redis backend tests (fakeredis)
    # ------------------------------------------------------------------

    @pytest.fixture
    def fake_redis_backend(self) -> RedisRateLimiterBackend:
        """Create a RedisRateLimiterBackend backed by fakeredis (async)."""
        import fakeredis

        client = fakeredis.FakeAsyncRedis()
        return RedisRateLimiterBackend(client)

    @pytest.fixture
    def redis_limiter(
        self, fake_redis_backend: RedisRateLimiterBackend
    ) -> SlidingWindowRateLimiter:
        return SlidingWindowRateLimiter(
            backend=fake_redis_backend,
            max_requests=3,
            window_seconds=1.0,
        )

    @pytest.mark.asyncio
    async def test_redis_first_request_allowed(
        self, redis_limiter: SlidingWindowRateLimiter
    ) -> None:
        """First request via Redis backend is allowed."""
        allowed, info = await redis_limiter.record("redis-user")
        assert allowed is True
        assert info["current_count"] == 1

    @pytest.mark.asyncio
    async def test_redis_rate_limit_enforced(
        self, redis_limiter: SlidingWindowRateLimiter
    ) -> None:
        """Redis backend enforces rate limit."""
        for _ in range(3):
            allowed, _ = await redis_limiter.record("redis-user")
            assert allowed is True
        allowed, info = await redis_limiter.record("redis-user")
        assert allowed is False
        assert info["remaining"] == 0

    @pytest.mark.asyncio
    async def test_redis_per_key_isolation(
        self, redis_limiter: SlidingWindowRateLimiter
    ) -> None:
        """Redis backend tracks keys independently."""
        for _ in range(3):
            await redis_limiter.record("key-A")
        allowed, _ = await redis_limiter.record("key-A")
        assert allowed is False

        allowed, info = await redis_limiter.record("key-B")
        assert allowed is True
        assert info["current_count"] == 1

    @pytest.mark.asyncio
    async def test_redis_check_does_not_record(
        self, redis_limiter: SlidingWindowRateLimiter
    ) -> None:
        """check() via Redis does NOT record."""
        allowed, info = await redis_limiter.check("check-key")
        assert allowed is True
        assert info["current_count"] == 0

    @pytest.mark.asyncio
    async def test_redis_remaining(
        self, redis_limiter: SlidingWindowRateLimiter
    ) -> None:
        """remaining() via Redis returns correct quota."""
        assert await redis_limiter.remaining("r-key") == 3
        await redis_limiter.record("r-key")
        assert await redis_limiter.remaining("r-key") == 2

    @pytest.mark.asyncio
    async def test_redis_reset(
        self, redis_limiter: SlidingWindowRateLimiter
    ) -> None:
        """reset() via Redis clears state."""
        for _ in range(3):
            await redis_limiter.record("reset-key")
        allowed, _ = await redis_limiter.record("reset-key")
        assert allowed is False
        await redis_limiter.reset("reset-key")
        allowed, _ = await redis_limiter.record("reset-key")
        assert allowed is True

    # ------------------------------------------------------------------
    # Redis backend direct tests
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_redis_backend_add_and_count(
        self, fake_redis_backend: RedisRateLimiterBackend
    ) -> None:
        """Redis backend stores and counts timestamps."""
        now = time.monotonic()
        await fake_redis_backend.add_timestamp("zkey", now, 10.0)
        await fake_redis_backend.add_timestamp("zkey", now + 0.1, 10.0)
        count = await fake_redis_backend.count_recent("zkey", 10.0, now + 0.2)
        assert count == 2

    @pytest.mark.asyncio
    async def test_redis_backend_get_oldest(
        self, fake_redis_backend: RedisRateLimiterBackend
    ) -> None:
        """Redis backend returns oldest timestamp."""
        now = time.monotonic()
        await fake_redis_backend.add_timestamp("oldest", now + 5, 100.0)
        await fake_redis_backend.add_timestamp("oldest", now, 100.0)
        oldest = await fake_redis_backend.get_oldest("oldest")
        assert oldest is not None
        assert oldest == pytest.approx(now, abs=0.01)

    @pytest.mark.asyncio
    async def test_redis_backend_clear(
        self, fake_redis_backend: RedisRateLimiterBackend
    ) -> None:
        """Redis backend clear removes the key."""
        await fake_redis_backend.add_timestamp("cx", time.monotonic(), 10.0)
        await fake_redis_backend.clear("cx")
        count = await fake_redis_backend.count_recent("cx", 10.0, time.monotonic())
        assert count == 0


# ════════════════════════════════════════════════════════════════════════════════
# TestRedisTokenBucket (Redis backend for TokenBucket via fakeredis)
# ════════════════════════════════════════════════════════════════════════════════


class TestRedisTokenBucket:
    """TokenBucket with fakeredis backend — verifies Redis integration path."""

    @pytest.fixture
    def fake_redis_tb_backend(self) -> RedisTokenBucketBackend:
        import fakeredis

        client = fakeredis.FakeAsyncRedis()
        return RedisTokenBucketBackend(client)

    @pytest.fixture
    def redis_bucket(
        self, fake_redis_tb_backend: RedisTokenBucketBackend
    ) -> TokenBucket:
        return TokenBucket(
            backend=fake_redis_tb_backend,
            key="redis:bucket:test",
            rate=10.0,
            capacity=5,
            ttl=3600.0,
        )

    @pytest.mark.asyncio
    async def test_redis_bucket_try_acquire(
        self, redis_bucket: TokenBucket
    ) -> None:
        """try_acquire works with Redis backend."""
        assert await redis_bucket.try_acquire(1) is True
        assert await redis_bucket.try_acquire(1) is True

    @pytest.mark.asyncio
    async def test_redis_bucket_exhaustion(
        self, redis_bucket: TokenBucket
    ) -> None:
        """Redis bucket respects capacity."""
        for _ in range(5):
            assert await redis_bucket.try_acquire(1) is True
        assert await redis_bucket.try_acquire(1) is False

    @pytest.mark.asyncio
    async def test_redis_bucket_shared_state(
        self, fake_redis_tb_backend: RedisTokenBucketBackend
    ) -> None:
        """Two buckets with same key share Redis state."""
        b1 = TokenBucket(
            fake_redis_tb_backend, "shared:redis:key", rate=10, capacity=5, ttl=3600
        )
        b2 = TokenBucket(
            fake_redis_tb_backend, "shared:redis:key", rate=10, capacity=5, ttl=3600
        )
        await b1.try_acquire(3)
        assert await b2.available_tokens() == 2.0

    @pytest.mark.asyncio
    async def test_redis_bucket_acquire_timeout(
        self, fake_redis_tb_backend: RedisTokenBucketBackend
    ) -> None:
        """acquire() times out on Redis backend."""
        bucket = TokenBucket(
            fake_redis_tb_backend, "redis:timeout", rate=1, capacity=1, ttl=3600
        )
        await bucket.try_acquire(1)
        result = await bucket.acquire(1, timeout=0.15)
        assert result is False

    @pytest.mark.asyncio
    async def test_redis_bucket_state_fields(
        self, redis_bucket: TokenBucket
    ) -> None:
        """State stored in Redis has expected fields."""
        await redis_bucket.try_acquire(2)
        state = await redis_bucket.current_state()
        assert state.tokens == 3.0
        assert state.max_tokens == 5.0
        assert state.refill_rate == 10.0
        assert state.last_refill > 0
