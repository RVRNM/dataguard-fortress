"""
Multi-tenant manager for DataGuard Fortress.

Loads per-tenant YAML configuration from a `tenants/` directory and provides
hot-reload via periodic async scanning.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Pydantic config models
# ---------------------------------------------------------------------------

class TenantRateLimit(BaseModel):
    """Rate-limit overrides for a tenant."""
    requests_per_second: float = Field(default=10.0, ge=0.0)
    burst_size: int = Field(default=20, ge=1)
    max_concurrent: int = Field(default=5, ge=1)
    window_seconds: int = Field(default=60, ge=1)


class TenantScrubber(BaseModel):
    """Scrubber configuration for a tenant."""
    enabled: bool = True
    pii_presets: list[str] = Field(default_factory=list)
    custom_patterns: dict[str, str] = Field(default_factory=dict)
    redact_headers: list[str] = Field(default_factory=list)
    redact_query_params: list[str] = Field(default_factory=list)
    mask_partial: bool = Field(default=False)
    hash_salt: str | None = None


class TenantConfig(BaseModel):
    """Full configuration for a single tenant."""
    tenant_id: str
    name: str | None = None
    description: str | None = None
    enabled: bool = True
    rate_limit: TenantRateLimit = Field(default_factory=TenantRateLimit)
    scrubber: TenantScrubber = Field(default_factory=TenantScrubber)
    allowed_upstreams: list[str] = Field(default_factory=list)
    custom_pii_presets: dict[str, list[str]] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Default tenant config
# ---------------------------------------------------------------------------

DEFAULT_TENANT = TenantConfig(
    tenant_id="default",
    name="Default Tenant",
    description="Fallback tenant when no explicit match is found",
    enabled=True,
    rate_limit=TenantRateLimit(
        requests_per_second=5.0,
        burst_size=10,
        max_concurrent=3,
        window_seconds=60,
    ),
    scrubber=TenantScrubber(
        enabled=True,
        pii_presets=["email", "phone", "ssn"],
        mask_partial=False,
    ),
    allowed_upstreams=[],
    custom_pii_presets={},
)


# ---------------------------------------------------------------------------
# TenantManager
# ---------------------------------------------------------------------------

class TenantManager:
    """
    Loads per-tenant YAML config from a ``tenants/`` directory and watches
    for changes with an async periodic scan (default every 60 seconds).

    Usage::

        manager = TenantManager(Path("./tenants"))
        await manager.start()           # begins hot-reload watcher
        cfg = manager.get_tenant("acme")
        all_ids = manager.list_tenants()
        await manager.stop()            # stops the watcher
    """

    def __init__(
        self,
        tenants_dir: Path,
        scan_interval: float = 60.0,
        default_tenant: TenantConfig | None = None,
    ) -> None:
        """
        Args:
            tenants_dir: Path to the directory that holds ``<tenant_id>.yml`` files.
            scan_interval: Seconds between periodic directory scans for hot-reload.
            default_tenant: Fallback TenantConfig.  If *None*, the built-in
                ``DEFAULT_TENANT`` is used.
        """
        self._tenants_dir = Path(tenants_dir)
        self._scan_interval = scan_interval
        self._default_tenant = default_tenant or DEFAULT_TENANT
        self._tenants: dict[str, TenantConfig] = {}
        self._file_mtimes: dict[str, float] = {}
        self._task: asyncio.Task | None = None
        self._running = False

        # Load once synchronously so the manager is usable immediately
        self.reload()

    # ------------------------------------------------------------------
    # Public synchronous API
    # ------------------------------------------------------------------

    def get_tenant(self, tenant_id: str) -> TenantConfig:
        """
        Return the ``TenantConfig`` for *tenant_id*.

        Falls back to the default tenant (with ``tenant_id`` rewritten to the
        requested id) when no explicit config is loaded.
        """
        if tenant_id in self._tenants:
            return self._tenants[tenant_id]
        logger.info("Tenant %r not found – returning default fallback", tenant_id)
        return self._default_tenant.model_copy(update={"tenant_id": tenant_id})

    def list_tenants(self) -> list[str]:
        """Return a sorted list of all loaded tenant IDs."""
        return sorted(self._tenants.keys())

    def reload(self) -> None:
        """
        Scan the ``tenants/`` directory and (re)load every ``*.yml`` / ``*.yaml``
        file.  New and changed files are (re)parsed; removed files are purged.
        """
        self._tenants_dir.mkdir(parents=True, exist_ok=True)

        current_ids: set[str] = set()
        for ext in ("*.yml", "*.yaml"):
            for fpath in sorted(self._tenants_dir.glob(ext)):
                tenant_id = fpath.stem
                current_ids.add(tenant_id)
                mtime = fpath.stat().st_mtime

                # Skip files we've already loaded and that haven't changed
                if tenant_id in self._file_mtimes and self._file_mtimes[tenant_id] == mtime:
                    continue

                try:
                    cfg = self._parse_file(fpath)
                    self._tenants[cfg.tenant_id] = cfg
                    self._file_mtimes[tenant_id] = mtime
                    logger.info("Loaded tenant config: %s (from %s)", cfg.tenant_id, fpath)
                except Exception:
                    logger.exception("Failed to load tenant config from %s", fpath)

        # Purge tenants whose files were removed
        removed = set(self._tenants.keys()) - current_ids
        for tid in removed:
            del self._tenants[tid]
            self._file_mtimes.pop(tid, None)
            logger.info("Removed tenant config: %s", tid)

    # ------------------------------------------------------------------
    # Async hot-reload watcher
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Start the periodic directory scanner."""
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._watch_loop())
        logger.info(
            "TenantManager watcher started (interval=%.1fs, dir=%s)",
            self._scan_interval,
            self._tenants_dir,
        )

    async def stop(self) -> None:
        """Stop the periodic directory scanner."""
        self._running = False
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None
        logger.info("TenantManager watcher stopped")

    async def _watch_loop(self) -> None:
        """Background coroutine that reloads tenants on a fixed interval."""
        while self._running:
            try:
                await asyncio.sleep(self._scan_interval)
                if self._running:
                    self.reload()
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("Unexpected error in tenant watcher loop")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_file(path: Path) -> TenantConfig:
        """Parse a single YAML file into a :class:`TenantConfig`."""
        with open(path, encoding="utf-8") as fh:
            raw = yaml.safe_load(fh) or {}
        if not isinstance(raw, dict):
            raise ValueError(f"Expected YAML mapping at top level, got {type(raw).__name__}")
        return TenantConfig(**raw)

    # ------------------------------------------------------------------
    # Context-manager support (optional convenience)
    # ------------------------------------------------------------------

    async def __aenter__(self) -> TenantManager:
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.stop()

    # ------------------------------------------------------------------
    # Introspection helpers
    # ------------------------------------------------------------------

    @property
    def tenants_dir(self) -> Path:
        return self._tenants_dir

    @property
    def scan_interval(self) -> float:
        return self._scan_interval

    @property
    def is_watching(self) -> bool:
        return self._running

    def __len__(self) -> int:
        return len(self._tenants)

    def __contains__(self, tenant_id: str) -> bool:
        return tenant_id in self._tenants

    def __repr__(self) -> str:
        return (
            f"<TenantManager dir={self._tenants_dir!s} "
            f"tenants={len(self._tenants)} watching={self._running}>"
        )
