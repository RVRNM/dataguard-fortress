"""DataGuard Orchestrator — central coordination for proxy request processing.

Ties together tenant resolution, rate limiting, classification, scrubbing,
and audit logging into a single async pipeline that the proxy server calls
before forwarding requests and after receiving responses.

Usage::

    orchestrator = DataGuardOrchestrator(config)
    await orchestrator.start()
    decision = await orchestrator.process_request(ctx, body)
    # decision.forward — whether to allow (always True for v0.4)
    # decision.classification — ClassificationResult
    # decision.tenant — TenantConfig
    await orchestrator.record_response(ctx, decision, scrub_count)
    await orchestrator.stop()
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from src.classifier import ClassificationResult, DataClassifier, SensitivityLevel
from src.config import Config
from src.tenant import TenantManager, TenantConfig
from src.token_bucket import (
    MemoryTokenBucketBackend,
    TenantTokenBuckets,
    TokenBucketBackend,
)
from src.sliding_window_ratelimiter import (
    MemoryRateLimiterBackend,
    SlidingWindowRateLimiter,
    RateLimiterBackend,
)

logger = logging.getLogger(__name__)


@dataclass
class OrchestratorDecision:
    """Result of the orchestrator's pre-forward processing."""

    forward: bool = True
    classification: Optional[ClassificationResult] = None
    tenant: Optional[TenantConfig] = None
    rate_limited: bool = False
    rate_limit_info: dict[str, Any] = field(default_factory=dict)
    tenant_id: str = "default"
    scrub_count: int = 0


class DataGuardOrchestrator:
    """Central orchestrator that coordinates tenant resolution, rate limiting,
    classification, and audit event recording for the proxy.

    Designed for v0.4: always forwards requests (no blocking), but enriches
    the response with classification headers and records audit events.

    Args:
        config: Application configuration.
        tenant_manager: Optional pre-initialized TenantManager. If None,
            one is created from config.
        classifier: Optional pre-initialized DataClassifier. If None,
            one is created with default settings.
    """

    def __init__(
        self,
        config: Config,
        tenant_manager: Optional[TenantManager] = None,
        classifier: Optional[DataClassifier] = None,
    ) -> None:
        self._config = config

        # Tenant manager
        if tenant_manager is not None:
            self._tenant_manager = tenant_manager
        else:
            self._tenant_manager = TenantManager(
                tenants_dir="./tenants",
                scan_interval=60.0,
            )

        # Classifier
        self._classifier = classifier or DataClassifier()

        # Rate limiters — one per tenant via factory
        self._token_bucket_backend: TokenBucketBackend = MemoryTokenBucketBackend()
        self._tenant_token_buckets = TenantTokenBuckets(
            backend=self._token_bucket_backend,
            rate=config.ratelimiter.rate,
            capacity=config.ratelimiter.capacity,
        )

        # Sliding-window rate limiter (stricter per-window limits)
        self._sliding_window_backend: RateLimiterBackend = MemoryRateLimiterBackend()
        self._sliding_window = SlidingWindowRateLimiter(
            backend=self._sliding_window_backend,
            max_requests=config.ratelimiter.per_minute,
            window_seconds=60.0,
        )

        self._running = False
        self._reload_task: Optional[asyncio.Task[None]] = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Start background tasks (tenant hot-reload)."""
        if self._running:
            return
        self._running = True

        # Start tenant watcher
        await self._tenant_manager.start()

        # Start periodic reload task (every 60s as fallback)
        self._reload_task = asyncio.create_task(self._reload_loop())

        logger.info("DataGuardOrchestrator started")

    async def stop(self) -> None:
        """Stop background tasks."""
        self._running = False

        if self._reload_task is not None:
            self._reload_task.cancel()
            try:
                await self._reload_task
            except asyncio.CancelledError:
                pass
            self._reload_task = None

        await self._tenant_manager.stop()
        logger.info("DataGuardOrchestrator stopped")

    async def _reload_loop(self) -> None:
        """Periodically reload tenants every 60 seconds."""
        while self._running:
            try:
                await asyncio.sleep(60.0)
                if self._running:
                    self._tenant_manager.reload()
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("Error in tenant reload loop")

    # ------------------------------------------------------------------
    # Request processing
    # ------------------------------------------------------------------

    def resolve_tenant(self, tenant_id: str) -> TenantConfig:
        """Resolve tenant from the X-Tenant-ID header value.

        Falls back to the default tenant if tenant_id is empty or unknown.
        """
        if not tenant_id:
            tenant_id = "default"
        return self._tenant_manager.get_tenant(tenant_id)

    async def check_rate_limit(self, tenant_id: str) -> tuple[bool, dict]:
        """Check both token-bucket and sliding-window rate limits for a tenant.

        Returns:
            Tuple of (allowed, info_dict). For v0.4, always returns True
            but records the info for audit purposes.
        """
        # Token bucket check
        bucket = self._tenant_token_buckets.get_bucket(tenant_id)
        tb_allowed = await bucket.try_acquire()

        # Sliding window check
        sw_allowed, sw_info = await self._sliding_window.check(f"sw:tenant:{tenant_id}")

        info = {
            "token_bucket_allowed": tb_allowed,
            "token_bucket_remaining": (await bucket.available_tokens()),
            "sliding_window": sw_info,
        }

        # v0.4: always allow, but track info
        return True, info

    async def classify_body(self, body: Optional[bytes]) -> ClassificationResult:
        """Classify the request body.

        Returns PUBLIC for empty/missing bodies.
        """
        if not body:
            return ClassificationResult(
                level=SensitivityLevel.PUBLIC,
                score=0.0,
                reasons=["empty_body"],
                pii_density=0.0,
            )
        text = body.decode("utf-8", errors="replace")
        return await self._classifier.classify(text)

    async def process_request(
        self,
        tenant_id: str,
        body: Optional[bytes] = None,
    ) -> OrchestratorDecision:
        """Process a request through the full pipeline (tenant resolution,
        rate limiting, classification).

        Called before forwarding the request upstream.

        Args:
            tenant_id: Tenant ID from X-Tenant-ID header.
            body: Request body bytes (may be None or empty).

        Returns:
            OrchestratorDecision with forward=True (always for v0.4),
            classification result, and tenant config.
        """
        start = time.monotonic()

        # 1. Resolve tenant
        tenant = self.resolve_tenant(tenant_id)

        # 2. Check rate limits (non-blocking in v0.4)
        rate_allowed, rate_info = await self.check_rate_limit(tenant.tenant_id)

        # 3. Classify body
        classification = await self.classify_body(body)

        elapsed = (time.monotonic() - start) * 1000
        logger.debug(
            "Orchestrator processed request for tenant=%s in %.2fms (level=%s)",
            tenant.tenant_id,
            elapsed,
            classification.level_name,
        )

        return OrchestratorDecision(
            forward=True,
            classification=classification,
            tenant=tenant,
            rate_limited=not rate_allowed,
            rate_limit_info=rate_info,
            tenant_id=tenant.tenant_id,
        )

    # ------------------------------------------------------------------
    # Response processing / audit
    # ------------------------------------------------------------------

    async def record_response(
        self,
        request_id: str,
        decision: OrchestratorDecision,
        scrub_count: int = 0,
        bytes_upstream: int = 0,
        bytes_downstream: int = 0,
        duration_ms: float = 0.0,
        error: str = "",
    ) -> dict[str, Any]:
        """Record an audit event after the response has been proxied.

        Builds a structured dict suitable for AuditLogger.log().

        Args:
            request_id: Unique request identifier.
            decision: The OrchestratorDecision from process_request().
            scrub_count: Number of PII entities scrubbed.
            bytes_upstream: Bytes sent upstream.
            bytes_downstream: Bytes received downstream.
            duration_ms: Total request duration in milliseconds.
            error: Error string if the request failed.

        Returns:
            Dict with audit event fields.
        """
        classification = decision.classification
        tenant = decision.tenant

        event_data = {
            "event_type": "proxy_request",
            "request_id": request_id,
            "tenant_id": decision.tenant_id,
            "sensitivity": classification.level_name if classification else "PUBLIC",
            "sensitivity_score": classification.score if classification else 0.0,
            "pii_density": classification.pii_density if classification else 0.0,
            "scrub_count": scrub_count,
            "rate_limited": decision.rate_limited,
            "rate_limit_info": decision.rate_limit_info,
            "bytes_upstream": bytes_upstream,
            "bytes_downstream": bytes_downstream,
            "duration_ms": duration_ms,
            "error": error,
            "tenant_name": tenant.name if tenant else None,
            "classification_reasons": classification.reasons if classification else [],
        }

        return event_data

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    @property
    def tenant_manager(self) -> TenantManager:
        return self._tenant_manager

    @property
    def classifier(self) -> DataClassifier:
        return self._classifier

    @property
    def is_running(self) -> bool:
        return self._running

    def get_tenant_headers(self, tenant: TenantConfig) -> dict[str, str]:
        """Return response headers that carry tenant/classification info.

        These are added to the upstream request so the tenant context
        propagates.
        """
        return {
            "X-Tenant-ID": tenant.tenant_id,
            "X-Tenant-Name": tenant.name or "",
        }

    def __repr__(self) -> str:
        return (
            f"<DataGuardOrchestrator running={self._running} "
            f"tenants={len(self._tenant_manager)}>"
        )
