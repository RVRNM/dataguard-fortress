"""DataGuard FastAPI Dashboard — web UI for monitoring and management.

Provides:
  - GET /api/              — health check
  - GET /api/stats         — proxy statistics (requests_total, pii_detected, blocked, rps)
  - GET /api/presets       — list all 52 PII presets
  - POST /api/scrub        — test scrubbing on text
  - GET /api/audit/recent  — recent audit events
  - GET /events            — SSE stream for live updates
  - GET /                  — serve HTML dashboard

Tenant management:
  - GET    /api/tenants             — list all tenants
  - POST   /api/tenants/{id}/reload — hot-reload a single tenant
  - GET    /api/tenants/{id}        — get tenant config
  - PUT    /api/tenants/{id}        — update tenant (hot-reload)
  - DELETE /api/tenants/{id}        — delete tenant

Classification:
  - POST /api/classify             — classify text sensitivity
  - GET  /api/classifier/levels    — list sensitivity levels

Rate limiting:
  - GET  /api/rate-limits           — current rate limit stats
  - POST /api/rate-limits/reset     — reset rate limiter
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, AsyncGenerator, Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from starlette.requests import Request

import yaml

from .classifier import ClassificationResult, DataClassifier, SensitivityLevel
from .config import Config
from .scrubber import PIIScrubber, ScrubResult
from .sliding_window_ratelimiter import (
    MemoryRateLimiterBackend,
    RateLimiterBackend,
    SlidingWindowRateLimiter,
)
from .tenant import TenantConfig, TenantManager
from .token_bucket import MemoryTokenBucketBackend, TenantTokenBuckets

logger = logging.getLogger(__name__)


# ── Live Stats Tracker ──────────────────────────────────────────────────────


@dataclass
class LiveStats:
    """Thread-safe live statistics tracker for the proxy.

    This is updated by the proxy server on each request and read by the
    dashboard API. Uses a simple lock-free approach with atomic-ish updates.
    """

    requests_total: int = 0
    pii_detected: int = 0
    requests_blocked: int = 0
    _window: deque[tuple[float, int]] = field(default_factory=lambda: deque(maxlen=1000))
    _start_time: float = field(default_factory=time.monotonic)

    def record_request(self, pii_count: int = 0, blocked: bool = False) -> None:
        """Record a completed request."""
        self.requests_total += 1
        self.pii_detected += pii_count
        if blocked:
            self.requests_blocked += 1
        self._window.append((time.monotonic(), pii_count))

    @property
    def requests_per_second(self) -> float:
        """Calculate requests per second over the last 10-second window."""
        now = time.monotonic()
        cutoff = now - 10.0
        recent = [t for t, _ in self._window if t >= cutoff]
        if len(recent) < 2:
            return 0.0
        span = recent[-1] - recent[0]
        if span <= 0:
            return 0.0
        return round(len(recent) / span, 2)

    def to_dict(self) -> dict[str, Any]:
        """Return stats as a dictionary."""
        return {
            "requests_total": self.requests_total,
            "pii_detected": self.pii_detected,
            "requests_blocked": self.requests_blocked,
            "requests_per_second": self.requests_per_second,
            "uptime_seconds": round(time.monotonic() - self._start_time, 1),
        }


# ── SSE Event Broker ────────────────────────────────────────────────────────


class EventBroker:
    """Pub/sub broker for Server-Sent Events.

    Maintains a set of subscriber queues and broadcasts events to all
    connected clients. Also keeps a ring buffer of recent events for
    late-joining clients.
    """

    def __init__(self, history_size: int = 200) -> None:
        self._subscribers: set[asyncio.Queue[str]] = set()
        self._history: deque[dict[str, Any]] = deque(maxlen=history_size)
        self._lock = asyncio.Lock()

    async def subscribe(self) -> asyncio.Queue[str]:
        """Subscribe to the event stream. Returns a queue that receives SSE-formatted events."""
        queue: asyncio.Queue[str] = asyncio.Queue(maxsize=100)
        async with self._lock:
            self._subscribers.add(queue)
        return queue

    async def unsubscribe(self, queue: asyncio.Queue[str]) -> None:
        """Remove a subscriber."""
        async with self._lock:
            self._subscribers.discard(queue)

    async def publish(self, event_type: str, data: dict[str, Any]) -> None:
        """Broadcast an event to all subscribers."""
        event_data = {"event_type": event_type, "timestamp": time.time(), "data": data}
        self._history.append(event_data)

        # Format as SSE
        sse_payload = f"event: {event_type}\ndata: {json.dumps(event_data, default=str)}\n\n"

        async with self._lock:
            dead: set[asyncio.Queue[str]] = set()
            for queue in self._subscribers:
                try:
                    queue.put_nowait(sse_payload)
                except asyncio.QueueFull:
                    dead.add(queue)
            for queue in dead:
                self._subscribers.discard(queue)

    def get_history(self, limit: int = 50) -> list[dict[str, Any]]:
        """Return recent events from the history buffer."""
        return list(self._history)[-limit:]


# ── Preset Info Extractor ───────────────────────────────────────────────────


def _extract_preset_details(scrubber: PIIScrubber) -> list[dict[str, Any]]:
    """Extract detailed information about all active presets from the scrubber."""
    presets: list[dict[str, Any]] = []
    for preset in scrubber._presets:
        presets.append({
            "name": preset.name,
            "entity_type": preset.entity_type,
            "replacement": preset.replacement,
            "confidence": preset.confidence,
            "pattern": preset.pattern.pattern,
        })
    return presets


# ── Sensitivity Level Descriptions ─────────────────────────────────────────

_SENSITIVITY_DESCRIPTIONS: dict[str, str] = {
    "PUBLIC": "Information intended for public consumption. No restrictions on distribution.",
    "INTERNAL": "Internal business information. Limited to employees and authorized contractors.",
    "CONFIDENTIAL": "Sensitive business data. Access restricted to specific teams or roles.",
    "RESTRICTED": "Highly sensitive data (PII, credentials, health records). Strictest access controls.",
}


# ── Dashboard Factory ───────────────────────────────────────────────────────

# Module-level singletons (set by create_dashboard)
_live_stats = LiveStats()
_event_broker = EventBroker()


def get_live_stats() -> LiveStats:
    """Return the module-level LiveStats singleton."""
    return _live_stats


def get_event_broker() -> EventBroker:
    """Return the module-level EventBroker singleton."""
    return _event_broker


def create_dashboard(
    config: Config,
    scrubber: PIIScrubber,
    get_stats: Optional[callable] = None,
    get_recent_audits: Optional[callable] = None,
    tenant_manager: Optional[TenantManager] = None,
    classifier: Optional[DataClassifier] = None,
    rate_limiter: Optional[SlidingWindowRateLimiter] = None,
    token_buckets: Optional[TenantTokenBuckets] = None,
) -> FastAPI:
    """Create the FastAPI dashboard app.

    Args:
        config: Application configuration.
        scrubber: PIIScrubber instance for testing and preset listing.
        get_stats: Optional callable returning proxy stats dict.
            If None, uses the module-level LiveStats tracker.
        get_recent_audits: Optional callable(limit) returning recent audit events.
            If None, returns an empty list.
        tenant_manager: Optional TenantManager for tenant CRUD endpoints.
        classifier: Optional DataClassifier for text sensitivity classification.
        rate_limiter: Optional SlidingWindowRateLimiter for rate-limit stats/reset.
        token_buckets: Optional TenantTokenBuckets for per-tenant token-bucket stats.
    """

    app = FastAPI(
        title="DataGuard Dashboard",
        description="Privacy proxy monitoring and management",
        version="1.0.0",
    )

    templates = Jinja2Templates(directory="src/dashboard/templates")

    # ── Resolve optional services with lazy defaults ────────────────────────

    _classifier = classifier or DataClassifier()

    if tenant_manager is None:
        try:
            tenant_manager = TenantManager(Path("tenants"))
        except Exception:
            logger.warning("Could not create default TenantManager; tenant APIs will return 503")

    if rate_limiter is None:
        _backend = MemoryRateLimiterBackend()
        rate_limiter = SlidingWindowRateLimiter(
            backend=_backend,
            max_requests=config.ratelimiter.per_minute,
            window_seconds=60.0,
        )

    if token_buckets is None:
        _tb_backend = MemoryTokenBucketBackend()
        token_buckets = TenantTokenBuckets(
            backend=_tb_backend,
            rate=config.ratelimiter.rate,
            capacity=config.ratelimiter.capacity,
        )

    # ── Resolve callbacks ───────────────────────────────────────────────

    def _get_stats() -> dict[str, Any]:
        """Get proxy stats — prefer external callback, fall back to live stats."""
        if get_stats is not None:
            try:
                external = get_stats()
                if isinstance(external, dict):
                    # Merge with live stats (external takes precedence for overlapping keys)
                    merged = _live_stats.to_dict()
                    merged.update(external)
                    return merged
            except Exception as exc:
                logger.warning("External get_stats callback failed: %s", exc)
        return _live_stats.to_dict()

    async def _get_recent_audits(limit: int = 50) -> list[dict[str, Any]]:
        """Get recent audit events."""
        if get_recent_audits is not None:
            try:
                result = get_recent_audits(limit)
                if asyncio.iscoroutine(result):
                    return await result
                return result
            except Exception as exc:
                logger.warning("External get_recent_audits callback failed: %s", exc)
        return []

    # ── Health Check ─────────────────────────────────────────────────────

    @app.get("/api/")
    async def api_check() -> dict[str, Any]:
        """API health check endpoint."""
        return {
            "status": "ok",
            "service": "dataguard-dashboard",
            "version": "1.0.0",
            "uptime": time.time(),
            "presets_active": scrubber.preset_count,
        }

    # ── Stats ────────────────────────────────────────────────────────────

    @app.get("/api/stats")
    async def stats() -> dict[str, Any]:
        """Return proxy statistics."""
        return _get_stats()

    # ── Presets ──────────────────────────────────────────────────────────

    @app.get("/api/presets")
    async def presets() -> dict[str, Any]:
        """List all active PII detection presets."""
        details = _extract_preset_details(scrubber)
        return {
            "total": len(details),
            "presets": details,
        }

    # ── Scrub Test ───────────────────────────────────────────────────────

    @app.post("/api/scrub")
    async def scrub_test(body: dict[str, str]) -> dict[str, Any]:
        """Test scrubbing on provided text.

        Expects JSON body: {"text": "..."}
        Returns scrubbed text and detection details.
        """
        text = body.get("text", "")
        if not text:
            raise HTTPException(status_code=400, detail="Missing 'text' field")

        result: ScrubResult = await scrubber.scrub(text)

        # Publish event for live feed
        await _event_broker.publish("scrub_test", {
            "original_length": len(text),
            "detections": len(result.detections),
            "entity_types": list(set(d.entity_type for d in result.detections)),
        })

        return {
            "original_length": len(text),
            "scrubbed_length": len(result.scrubbed_text),
            "detections": len(result.detections),
            "scrubbed_text": result.scrubbed_text,
            "entities": [
                {
                    "type": d.entity_type,
                    "confidence": d.confidence,
                    "start": d.start,
                    "end": d.end,
                    "matched": d.matched_text[:50] + ("..." if len(d.matched_text) > 50 else ""),
                }
                for d in result.detections
            ],
        }

    # ── Audit Recent ─────────────────────────────────────────────────────

    @app.get("/api/audit/recent")
    async def audit_recent(limit: int = 50) -> dict[str, Any]:
        """Return recent audit events."""
        events = await _get_recent_audits(limit)
        return {
            "total": len(events),
            "events": events,
        }

    # ── SSE Event Stream ─────────────────────────────────────────────────

    @app.get("/events")
    async def events_stream(request: Request) -> StreamingResponse:
        """Server-Sent Events stream for live dashboard updates.

        Streams events as they occur: new requests, PII detections, scrub tests.
        """
        queue = await _event_broker.subscribe()

        async def event_generator() -> AsyncGenerator[str, None]:
            """Generate SSE events from the subscriber queue."""
            try:
                # Send initial connected event
                yield f"event: connected\ndata: {json.dumps({'status': 'connected', 'timestamp': time.time()})}\n\n"

                # Send recent history as replay
                history = _event_broker.get_history(20)
                for hist_event in history:
                    event_type = hist_event.get("event_type", "message")
                    yield f"event: {event_type}\ndata: {json.dumps(hist_event, default=str)}\n\n"

                # Keep-alive ping every 30 seconds
                while True:
                    try:
                        payload = await asyncio.wait_for(queue.get(), timeout=30.0)
                        yield payload
                    except asyncio.TimeoutError:
                        # Send keep-alive comment
                        yield f": ping {time.time()}\n\n"
            except asyncio.CancelledError:
                pass
            finally:
                await _event_broker.unsubscribe(queue)

        return StreamingResponse(
            event_generator(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    # ═══════════════════════════════════════════════════════════════════════
    # Tenant Management API
    # ═══════════════════════════════════════════════════════════════════════

    @app.get("/api/tenants")
    async def list_tenants() -> dict[str, Any]:
        """List all loaded tenants."""
        if tenant_manager is None:
            raise HTTPException(status_code=503, detail="TenantManager not available")
        tenant_ids = tenant_manager.list_tenants()
        tenants_info: list[dict[str, Any]] = []
        for tid in tenant_ids:
            cfg = tenant_manager.get_tenant(tid)
            tenants_info.append({
                "tenant_id": cfg.tenant_id,
                "name": cfg.name,
                "enabled": cfg.enabled,
            })
        return {
            "total": len(tenants_info),
            "tenants": tenants_info,
        }

    @app.get("/api/tenants/{tenant_id}")
    async def get_tenant(tenant_id: str) -> dict[str, Any]:
        """Get full configuration for a specific tenant."""
        if tenant_manager is None:
            raise HTTPException(status_code=503, detail="TenantManager not available")
        if tenant_id not in tenant_manager:
            raise HTTPException(status_code=404, detail=f"Tenant '{tenant_id}' not found")
        cfg = tenant_manager.get_tenant(tenant_id)
        return cfg.model_dump()

    @app.put("/api/tenants/{tenant_id}")
    async def update_tenant(tenant_id: str, body: dict[str, Any]) -> dict[str, Any]:
        """Update a tenant configuration (hot-reload).

        Accepts a partial or full TenantConfig as JSON body.
        Validates the full config, writes it to the tenants directory,
        and triggers a hot-reload.
        """
        if tenant_manager is None:
            raise HTTPException(status_code=503, detail="TenantManager not available")

        # Merge with existing config if tenant exists
        existing: Optional[TenantConfig] = None
        if tenant_id in tenant_manager:
            existing = tenant_manager.get_tenant(tenant_id)

        if existing is not None:
            merged = existing.model_dump()
            merged.update(body)
        else:
            merged = body
            merged.setdefault("tenant_id", tenant_id)

        # Ensure tenant_id matches the path parameter
        merged["tenant_id"] = tenant_id

        # Validate with Pydantic
        try:
            new_config = TenantConfig(**merged)
        except Exception as exc:
            raise HTTPException(status_code=422, detail=f"Invalid tenant config: {exc}")

        # Write to YAML file in the tenants directory
        tenants_dir = tenant_manager.tenants_dir
        tenants_dir.mkdir(parents=True, exist_ok=True)
        config_path = tenants_dir / f"{tenant_id}.yml"

        try:
            config_dict = new_config.model_dump()
            with open(config_path, "w", encoding="utf-8") as fh:
                yaml.dump(config_dict, fh, default_flow_style=False, sort_keys=False)
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Failed to write tenant config: {exc}")

        # Trigger hot-reload
        tenant_manager.reload()

        # Publish event
        await _event_broker.publish("tenant_updated", {
            "tenant_id": tenant_id,
            "action": "update",
        })

        return {
            "status": "ok",
            "tenant_id": tenant_id,
            "action": "updated",
            "config": new_config.model_dump(),
        }

    @app.delete("/api/tenants/{tenant_id}")
    async def delete_tenant(tenant_id: str) -> dict[str, Any]:
        """Delete a tenant by removing its config file and reloading."""
        if tenant_manager is None:
            raise HTTPException(status_code=503, detail="TenantManager not available")
        if tenant_id not in tenant_manager:
            raise HTTPException(status_code=404, detail=f"Tenant '{tenant_id}' not found")

        # Remove the YAML file
        tenants_dir = tenant_manager.tenants_dir
        removed_files: list[str] = []
        for ext in (".yml", ".yaml"):
            fpath = tenants_dir / f"{tenant_id}{ext}"
            if fpath.exists():
                try:
                    fpath.unlink()
                    removed_files.append(str(fpath))
                except Exception as exc:
                    raise HTTPException(
                        status_code=500,
                        detail=f"Failed to delete tenant file {fpath}: {exc}",
                    )

        # Trigger hot-reload (will purge the in-memory tenant)
        tenant_manager.reload()

        # Publish event
        await _event_broker.publish("tenant_deleted", {
            "tenant_id": tenant_id,
            "action": "delete",
            "removed_files": removed_files,
        })

        return {
            "status": "ok",
            "tenant_id": tenant_id,
            "action": "deleted",
            "removed_files": removed_files,
        }

    @app.post("/api/tenants/{tenant_id}/reload")
    async def reload_tenant(tenant_id: str) -> dict[str, Any]:
        """Force hot-reload of a single tenant's configuration from disk."""
        if tenant_manager is None:
            raise HTTPException(status_code=503, detail="TenantManager not available")

        # Reset mtime cache for this tenant so reload picks up changes
        if hasattr(tenant_manager, "_file_mtimes"):
            tenant_manager._file_mtimes.pop(tenant_id, None)

        tenant_manager.reload()

        if tenant_id not in tenant_manager:
            raise HTTPException(
                status_code=404,
                detail=f"Tenant '{tenant_id}' not found after reload",
            )

        cfg = tenant_manager.get_tenant(tenant_id)

        # Publish event
        await _event_broker.publish("tenant_reloaded", {
            "tenant_id": tenant_id,
            "action": "reload",
        })

        return {
            "status": "ok",
            "tenant_id": tenant_id,
            "action": "reloaded",
            "config": cfg.model_dump(),
        }

    # ═══════════════════════════════════════════════════════════════════════
    # Classification API
    # ═══════════════════════════════════════════════════════════════════════

    @app.post("/api/classify")
    async def classify_text(body: dict[str, str]) -> dict[str, Any]:
        """Classify text sensitivity level.

        Expects JSON body: {"text": "..."}
        Returns sensitivity level, score, reasons, and PII density.
        """
        text = body.get("text", "")
        if not text:
            raise HTTPException(status_code=400, detail="Missing 'text' field")

        result: ClassificationResult = await _classifier.classify(text)

        # Publish event
        await _event_broker.publish("classification", {
            "level": result.level_name,
            "score": result.score,
            "pii_density": result.pii_density,
            "reasons_count": len(result.reasons),
        })

        return {
            "level": result.level_name,
            "level_value": result.level.value,
            "score": result.score,
            "reasons": result.reasons,
            "pii_density": result.pii_density,
        }

    @app.get("/api/classifier/levels")
    async def classifier_levels() -> dict[str, Any]:
        """List all available sensitivity levels with descriptions."""
        levels = []
        for level in SensitivityLevel:
            levels.append({
                "name": level.name,
                "value": level.value,
                "description": _SENSITIVITY_DESCRIPTIONS.get(level.name, ""),
            })
        return {
            "total": len(levels),
            "levels": levels,
        }

    # ═══════════════════════════════════════════════════════════════════════
    # Rate Limiting API
    # ═══════════════════════════════════════════════════════════════════════

    @app.get("/api/rate-limits")
    async def rate_limits() -> dict[str, Any]:
        """Get current rate-limit stats across all tenants."""
        tenant_ids: list[str] = []
        if tenant_manager is not None:
            tenant_ids = tenant_manager.list_tenants()

        per_tenant: list[dict[str, Any]] = []
        for tid in tenant_ids:
            info: dict[str, Any] = {"tenant_id": tid}

            # Sliding-window stats
            if rate_limiter is not None:
                try:
                    _, sw_info = await rate_limiter.check(f"tenant:{tid}")
                    info["sliding_window"] = sw_info
                except Exception as exc:
                    info["sliding_window_error"] = str(exc)

            # Token-bucket stats
            if token_buckets is not None:
                try:
                    bucket = token_buckets.get_bucket(tid)
                    state = await bucket.current_state()
                    info["token_bucket"] = {
                        "available_tokens": round(state.tokens, 2),
                        "max_tokens": state.max_tokens,
                        "refill_rate": state.refill_rate,
                    }
                except Exception as exc:
                    info["token_bucket_error"] = str(exc)

            per_tenant.append(info)

        # Global config
        global_config: dict[str, Any] = {}
        if rate_limiter is not None:
            global_config["sliding_window"] = {
                "max_requests": rate_limiter.max_requests,
                "window_seconds": rate_limiter.window_seconds,
            }
        if token_buckets is not None:
            global_config["token_bucket"] = {
                "default_rate": token_buckets._rate,
                "default_capacity": token_buckets._capacity,
            }
        if tenant_manager is not None:
            global_config["tenants_dir"] = str(tenant_manager.tenants_dir)
            global_config["watching"] = tenant_manager.is_watching

        return {
            "config": global_config,
            "tenants": per_tenant,
            "total_tenants": len(per_tenant),
        }

    @app.post("/api/rate-limits/reset")
    async def rate_limits_reset(body: Optional[dict[str, str]] = None) -> dict[str, Any]:
        """Reset rate-limit state.

        Accepts optional JSON body: {"tenant_id": "acme"} to reset a single tenant,
        or an empty body / {"all": true} to reset all.
        """
        target_tenant: Optional[str] = None
        if body:
            target_tenant = body.get("tenant_id")

        reset_keys: list[str] = []

        if target_tenant:
            # Reset specific tenant
            key = f"tenant:{target_tenant}"
            if rate_limiter is not None:
                await rate_limiter.reset(key)
                reset_keys.append(f"sliding_window:{key}")
            if token_buckets is not None:
                bucket = token_buckets.get_bucket(target_tenant)
                await bucket.reset()
                reset_keys.append(f"token_bucket:{target_tenant}")
        else:
            # Reset all tenants
            tenant_ids: list[str] = []
            if tenant_manager is not None:
                tenant_ids = tenant_manager.list_tenants()

            for tid in tenant_ids:
                key = f"tenant:{tid}"
                if rate_limiter is not None:
                    await rate_limiter.reset(key)
                    reset_keys.append(f"sliding_window:{key}")
                if token_buckets is not None:
                    bucket = token_buckets.get_bucket(tid)
                    await bucket.reset()
                    reset_keys.append(f"token_bucket:{tid}")

            # Also clear the in-memory backend stores entirely
            if rate_limiter is not None and isinstance(
                rate_limiter._backend, MemoryRateLimiterBackend
            ):
                rate_limiter._backend.clear_all()
                reset_keys.append("sliding_window:all")

            if token_buckets is not None and isinstance(
                token_buckets._backend, MemoryTokenBucketBackend
            ):
                token_buckets._backend.clear()
                token_buckets.clear()
                reset_keys.append("token_bucket:all")

        # Publish event
        await _event_broker.publish("rate_limits_reset", {
            "target_tenant": target_tenant or "all",
            "reset_keys": reset_keys,
        })

        return {
            "status": "ok",
            "action": "reset",
            "target_tenant": target_tenant or "all",
            "reset_keys": reset_keys,
        }

    # ── HTML Dashboard ───────────────────────────────────────────────────

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request):
        """Serve the main dashboard HTML."""
        return templates.TemplateResponse(request, "index.html")

    return app
