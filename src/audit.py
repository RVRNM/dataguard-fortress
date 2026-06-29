"""Structured Audit Logger — append-only JSONL format with rotation.

Provides:
  - Buffered async writes for performance
  - Automatic log rotation by size
  - Gzip compression of rotated files
  - Thread-safe operations
"""

from __future__ import annotations

import asyncio
import contextlib
import gzip
import json
import logging
import shutil
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class AuditEventType(StrEnum):
    """Types of audit events."""
    REQUEST = "request"
    RESPONSE = "response"
    PROXY_CONNECT = "proxy_connect"
    PROXY_ERROR = "proxy_error"
    CONFIG_RELOAD = "config_reload"
    SCRUB = "scrub"
    RATE_LIMIT = "rate_limit"


@dataclass
class AuditEvent:
    """A single audit event.

    This is the core record written to the audit log.
    One JSON object per line in the JSONL file.
    """
    timestamp: str = ""
    event_type: str = ""
    request_id: str = ""
    client_ip: str = ""
    method: str = ""
    path: str = ""
    upstream: str = ""
    status_code: int = 0
    sensitivity: str = "PUBLIC"
    scrub_count: int = 0
    duration_ms: float = 0.0
    request_size_bytes: int = 0
    response_size_bytes: int = 0
    error: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def model_dump_json(self) -> str:
        """Serialize to JSON string for the JSONL file."""
        d = asdict(self)
        # Flatten extra fields into top level
        extra = d.pop("extra", {})
        d.update(extra)
        return json.dumps(d, default=str, ensure_ascii=False)


class AuditLogger:
    """Async audit logger with buffered JSONL writes and rotation.

    Writes audit events to a JSONL file with:
    - In-memory buffering (flush every N events or on timer)
    - Automatic rotation when file exceeds max_size_bytes
    - Gzip compression of rotated archives
    - Non-blocking errors (audit failure doesn't block proxy)

    Usage:
        audit = AuditLogger(AuditConfig())
        await audit.start()
        await audit.log(AuditEvent(event_type="request", ...))
        await audit.stop()
    """

    def __init__(self, config: Any | None = None) -> None:
        """Initialize the audit logger.

        Args:
            config: Configuration object with attributes:
                - enabled (bool)
                - log_dir (str)
                - log_filename (str)
                - max_size_mb (int)
                - buffer_size (int)
                - flush_interval_seconds (float)
                - redact_in_log (bool)
        """
        self._enabled: bool = True
        self._log_dir: Path = Path("./logs")
        self._log_filename: str = "audit.jsonl"
        self._max_size_bytes: int = 100 * 1024 * 1024  # 100 MB
        self._buffer_size: int = 100
        self._flush_interval: float = 1.0
        self._redact_in_log: bool = True

        if config is not None:
            self._enabled = getattr(config, "enabled", True)
            self._log_dir = Path(getattr(config, "log_dir", "./logs"))
            self._log_filename = getattr(config, "log_filename", "audit.jsonl")
            self._max_size_bytes = getattr(config, "max_size_mb", 100) * 1024 * 1024
            self._buffer_size = getattr(config, "buffer_size", 100)
            self._flush_interval = getattr(config, "flush_interval_seconds", 1.0)
            self._redact_in_log = getattr(config, "redact_in_log", True)

        self._buffer: list[str] = []
        self._lock = asyncio.Lock()
        self._flush_task: asyncio.Task[None] | None = None
        self._file: Any = None  # managed via aiofiles if available, else sync

    @property
    def log_path(self) -> Path:
        """Current active log file path."""
        return self._log_dir / self._log_filename

    async def start(self) -> None:
        """Start the audit logger: create dirs and launch flush timer."""
        if not self._enabled:
            logger.info("Audit logging disabled.")
            return

        self._log_dir.mkdir(parents=True, exist_ok=True)

        # Start periodic flush task
        self._flush_task = asyncio.create_task(self._periodic_flush())
        logger.info("Audit logger started: %s", self.log_path)

    async def stop(self) -> None:
        """Stop the logger: flush remaining buffer and cancel timer."""
        if self._flush_task:
            self._flush_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._flush_task

        await self._flush()
        logger.info("Audit logger stopped.")

    def close(self) -> None:
        """Synchronous close for compatibility. Flushes buffer immediately."""
        if not self._enabled:
            return
        # Run flush in a new event loop if needed
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                loop.create_task(self._flush())
            else:
                loop.run_until_complete(self._flush())
        except RuntimeError:
            # No event loop — create one
            asyncio.run(self._flush())
        logger.info("Audit logger closed (sync).")

    async def aclose(self) -> None:
        """Async close alias for stop()."""
        await self.stop()

    async def log(self, event: AuditEvent) -> None:
        """Log an audit event.

        Events are buffered and flushed periodically or when
        the buffer reaches its configured size.

        Args:
            event: The audit event to record.
        """
        if not self._enabled:
            return

        # Set timestamp if not provided
        if not event.timestamp:
            event.timestamp = datetime.now(UTC).isoformat()

        line = event.model_dump_json()

        async with self._lock:
            self._buffer.append(line)
            if len(self._buffer) >= self._buffer_size:
                await self._flush_unlocked()

    async def _periodic_flush(self) -> None:
        """Periodically flush the buffer on a timer."""
        while True:
            await asyncio.sleep(self._flush_interval)
            async with self._lock:
                if self._buffer:
                    await self._flush_unlocked()

    async def _flush(self) -> None:
        """Flush the buffer to disk (thread-safe entry point)."""
        async with self._lock:
            await self._flush_unlocked()

    async def _flush_unlocked(self) -> None:
        """Flush buffer to disk (caller must hold _lock)."""
        if not self._buffer:
            return

        try:
            # Check if we need to rotate
            await self._rotate_if_needed()

            # Write using asyncio-friendly approach
            content = "\n".join(self._buffer) + "\n"
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self._write_sync, content)

            self._buffer.clear()
        except Exception as exc:
            # Audit failure must not block the proxy
            logger.warning("Audit flush failed: %s", exc)

    def _write_sync(self, content: str) -> None:
        """Synchronous file write (run in executor)."""
        self._log_dir.mkdir(parents=True, exist_ok=True)
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(content)

    async def _rotate_if_needed(self) -> None:
        """Rotate the log file if it exceeds max size."""
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._rotate_if_needed_sync)

    def _rotate_if_needed_sync(self) -> None:
        """Synchronous rotation check."""
        if not self.log_path.exists():
            return

        if self.log_path.stat().st_size >= self._max_size_bytes:
            timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
            archive_name = f"audit_{timestamp}.jsonl.gz"
            archive_path = self._log_dir / archive_name

            # Compress the current file to archive
            with open(self.log_path, "rb") as f_in, gzip.open(archive_path, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)

            # Remove the original
            self.log_path.unlink()
            logger.info("Rotated audit log to %s", archive_path)

    async def query(
        self,
        limit: int = 100,
        event_type: str | None = None,
        since: str | None = None,
    ) -> list[dict[str, Any]]:
        """Query recent audit events (for API/debugging).

        Args:
            limit: Maximum number of events to return.
            event_type: Filter by event type.
            since: ISO timestamp to filter events after.

        Returns:
            List of event dicts.
        """
        events: list[dict[str, Any]] = []

        if not self.log_path.exists():
            return events

        loop = asyncio.get_event_loop()
        lines = await loop.run_in_executor(None, self._read_lines_sync)

        for line in reversed(lines):
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                if event_type and event.get("event_type") != event_type:
                    continue
                if since and event.get("timestamp", "") < since:
                    continue
                events.append(event)
                if len(events) >= limit:
                    break
            except json.JSONDecodeError:
                continue

        return events

    def _read_lines_sync(self) -> list[str]:
        """Read all lines from the log file."""
        try:
            with open(self.log_path, encoding="utf-8") as f:
                return f.readlines()
        except OSError:
            return []

    def get_stats(self) -> dict[str, Any]:
        """Get audit log statistics."""
        total_events = 0
        total_size = 0

        for f in self._log_dir.glob("audit*.jsonl*"):
            total_size += f.stat().st_size
            if f.suffix == ".jsonl":
                # Count lines in the active file
                try:
                    with open(f, encoding="utf-8") as fh:
                        total_events += sum(1 for line in fh if line.strip())
                except OSError:
                    pass

        return {
            "active_log": str(self.log_path),
            "active_log_exists": self.log_path.exists(),
            "total_events_approx": total_events,
            "total_size_bytes": total_size,
            "buffer_pending": len(self._buffer),
        }
