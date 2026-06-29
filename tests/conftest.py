"""Pytest configuration and shared fixtures for DataGuard Fortress tests."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

# Add project root to path for imports
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.audit import AuditEvent, AuditEventType, AuditLogger
from src.config import AuditConfig, Config, ProxyServerConfig, ScrubberConfig
from src.scrubber import PIIScrubber


@pytest.fixture
def event_loop():
    """Create a fresh event loop for each test."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def default_config() -> Config:
    """Provide a default Config instance for testing."""
    return Config(
        scrubber=ScrubberConfig(
            enabled=True,
            min_confidence=0.0,
        ),
        audit=AuditConfig(
            enabled=True,
            log_dir="./test_logs",
            buffer_size=10,
            flush_interval_seconds=0.1,
        ),
        proxy=ProxyServerConfig(
            host="127.0.0.1",
            port=0,  # let OS pick
            max_concurrent_connections=100,
        ),
    )


@pytest.fixture
def scrubber() -> PIIScrubber:
    """Provide a PIIScrubber with all presets enabled."""
    return PIIScrubber(min_confidence=0.0)


@pytest.fixture
def scrubber_strict() -> PIIScrubber:
    """Provide a PIIScrubber with high confidence threshold."""
    return PIIScrubber(min_confidence=0.80)


@pytest.fixture
def sample_pii_text() -> str:
    """Sample text containing various PII types."""
    return (
        "Contact: alice@example.com, phone: 555-123-4567. "
        "SSN: 123-45-6789. Card: 4111-1111-1111-1111. "
        "API key: sk-TEST-REDACTED. "
        "AWS key: TEST_AWS_KEY."
    )


@pytest.fixture
def sample_clean_text() -> str:
    """Sample text with no PII."""
    return "The quick brown fox jumps over the lazy dog. Hello world!"


@pytest.fixture
def audit_logger(tmp_path) -> AuditLogger:
    """Provide an AuditLogger with a temp directory."""
    config = AuditConfig(
        enabled=True,
        log_dir=str(tmp_path / "audit"),
        log_filename="test_audit.jsonl",
        buffer_size=5,
        flush_interval_seconds=0.1,
    )
    return AuditLogger(config=config)


@pytest.fixture
def sample_audit_event() -> AuditEvent:
    """Provide a sample audit event."""
    return AuditEvent(
        event_type=AuditEventType.REQUEST.value,
        request_id="test-123",
        client_ip="127.0.0.1",
        method="GET",
        path="/v1/chat/completions",
        upstream="openai",
        status_code=200,
        sensitivity="CONFIDENTIAL",
        scrub_count=3,
        duration_ms=12.5,
    )
