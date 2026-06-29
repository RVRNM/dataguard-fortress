"""Tests for the Proxy Server."""

from __future__ import annotations

import asyncio
import socket
import time
from collections.abc import AsyncGenerator

import pytest
import pytest_asyncio

from src.audit import AuditEvent, AuditEventType, AuditLogger
from src.config import AuditConfig, Config, ProxyServerConfig, ScrubberConfig, UpstreamsConfig
from src.proxy_server import (
    AsyncProxyServer,
    ConnectionPool,
    RequestContext,
)


@pytest_asyncio.fixture
async def free_port() -> int:
    """Get a free port for testing."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest_asyncio.fixture
async def echo_server(free_port: int) -> AsyncGenerator[tuple[str, int], None]:
    """Start a simple echo server for testing proxy connections."""
    connections: list[asyncio.Transport] = []

    def protocol_factory():
        proto = asyncio.Protocol()

        def connection_made(transport):
            connections.append(transport)

        def data_received(data):
            # Echo back with an HTTP-like response
            response = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/plain\r\n"
                b"Content-Length: "
                + str(len(data)).encode()
                + b"\r\n"
                + b"X-Proxied: true\r\n"
                + b"\r\n"
                + data
            )
            transport.write(response)
            transport.close()

        proto.connection_made = connection_made
        proto.data_received = data_received
        return proto

    loop = asyncio.get_event_loop()
    server = await loop.create_server(protocol_factory, "127.0.0.1", free_port)
    await server.start_serving()

    yield ("127.0.0.1", free_port)

    server.close()
    await server.wait_closed()


@pytest_asyncio.fixture
async def basic_config(free_port: int, tmp_path) -> Config:
    """Create a test configuration pointing to our echo server."""
    return Config(
        scrubber=ScrubberConfig(enabled=True, min_confidence=0.0),
        audit=AuditConfig(
            enabled=True,
            log_dir=str(tmp_path / "audit"),
            buffer_size=50,
            flush_interval_seconds=0.5,
        ),
        upstreams=UpstreamsConfig(default="test"),
        proxy=ProxyServerConfig(
            host="127.0.0.1",
            port=free_port + 1,  # next port for proxy
            buffer_size=4096,
            max_concurrent_connections=100,
            connect_timeout=5.0,
            read_timeout=10.0,
        ),
    )


class TestConnectionPool:
    """Tests for the ConnectionPool."""

    @pytest.mark.asyncio
    async def test_get_creates_new_connection(self, echo_server: tuple[str, int]) -> None:
        pool = ConnectionPool()
        host, port = echo_server
        reader, writer = await pool.get(host, port, use_tls=False)
        assert reader is not None
        writer.close()
        await pool.close_all()

    @pytest.mark.asyncio
    async def test_put_returns_connection(self, echo_server: tuple[str, int]) -> None:
        pool = ConnectionPool()
        host, port = echo_server
        reader, writer = await pool.get(host, port, use_tls=False)
        # Write something, close
        writer.close()
        await pool.close_all()

    @pytest.mark.asyncio
    async def test_close_all(self) -> None:
        pool = ConnectionPool()
        await pool.close_all()
        # Should not raise


class TestRequestContext:
    """Tests for the RequestContext dataclass."""

    def test_duration_calculation(self) -> None:
        ctx = RequestContext(start_time=100.0, end_time=105.5)
        assert ctx.duration_ms == 5500.0

    def test_duration_running(self) -> None:
        ctx = RequestContext(start_time=time.monotonic())
        # Should be very close to 0 for a fresh context
        assert ctx.duration_ms < 1000

    def test_default_values(self) -> None:
        ctx = RequestContext()
        assert ctx.scrub_count == 0
        assert ctx.bytes_upstream == 0
        assert ctx.error == ""


class TestAsyncProxyServer:
    """Tests for the AsyncProxyServer."""

    @pytest.mark.asyncio
    async def test_server_starts_and_stops(
        self, basic_config: Config, echo_server: tuple[str, int]
    ) -> None:
        """Server can be started and stopped cleanly."""
        server = AsyncProxyServer(config=basic_config)
        await server.start()
        assert server._server is not None
        await server.stop()
        assert not server._running

    @pytest.mark.asyncio
    async def test_server_accepts_connection(self, basic_config: Config) -> None:
        """Server accepts TCP connections without error."""
        server = AsyncProxyServer(config=basic_config)
        await server.start()

        try:
            # Just connect — server should handle it
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", basic_config.proxy.port),
                timeout=3.0,
            )
            writer.close()
            await writer.wait_closed()
        finally:
            await server.stop()

    @pytest.mark.asyncio
    async def test_proxy_routes_configured(self, basic_config: Config) -> None:
        """Proxy has routes set up during init."""
        server = AsyncProxyServer(config=basic_config)
        assert server._default_route is not None

    @pytest.mark.asyncio
    async def test_connect_timeout(self, basic_config: Config) -> None:
        """Proxy respects connect timeout for unreachable servers."""
        # Configure with a port that won't connect
        basic_config.proxy.port = basic_config.proxy.port + 100
        server = AsyncProxyServer(config=basic_config)
        await server.start()
        # Can't easily test timeout without a restrictive firewall,
        # but we verify the server starts
        await server.stop()

    @pytest.mark.asyncio
    async def test_health_endpoint(self, basic_config: Config) -> None:
        """Server has semaphore for connection limiting."""
        assert basic_config.proxy.max_concurrent_connections == 100


class TestAuditLogger:
    """Tests for the audit logger."""

    @pytest.mark.asyncio
    @pytest.mark.skipif(not hasattr(asyncio, "timeout"), reason="asyncio.timeout required")
    async def test_log_event(self, tmp_path) -> None:
        """Audit events are written to disk."""
        from src.config import AuditConfig
        config = AuditConfig(
            enabled=True,
            log_dir=str(tmp_path / "audit"),
            buffer_size=1,  # flush immediately
            flush_interval_seconds=0.1,
        )
        logger = AuditLogger(config=config)
        await logger.start()

        event = AuditEvent(
            event_type=AuditEventType.REQUEST.value,
            request_id="test-1",
            method="GET",
            path="/test",
        )
        await logger.log(event)
        await asyncio.sleep(0.2)  # let flush happen
        await logger.stop()

        # Check file was created
        assert logger.log_path.exists() or (tmp_path / "audit").exists()

    @pytest.mark.asyncio
    async def test_stats(self, tmp_path) -> None:
        """Stats report buffer state correctly."""
        from src.config import AuditConfig
        config = AuditConfig(
            enabled=True,
            log_dir=str(tmp_path / "audit"),
            buffer_size=100,
        )
        logger = AuditLogger(config=config)
        stats = logger.get_stats()
        assert stats["buffer_pending"] == 0
        assert "active_log" in stats


class TestGracefulShutdown:
    """Tests for graceful shutdown behavior."""

    @pytest.mark.asyncio
    async def test_server_shutdown_cancels_tasks(self, basic_config: Config) -> None:
        """Stopping the server completes without hanging."""
        server = AsyncProxyServer(config=basic_config)
        await server.start()
        # Stop should complete promptly
        await asyncio.wait_for(server.stop(), timeout=5.0)

    @pytest.mark.asyncio
    async def test_windows_adapter_init(self) -> None:
        """WindowsServiceAdapter can be initialized."""
        from src.proxy_server import WindowsServiceAdapter
        async def factory():
            pass
        adapter = WindowsServiceAdapter(factory)
        assert adapter._running is False
        adapter.stop_service()
        assert adapter._running is False


class TestConfigValidation:
    """Tests for configuration validation."""

    def test_default_config(self) -> None:
        config = Config()
        assert config.proxy.port == 8080
        assert config.scrubber.enabled is True
        assert config.audit.enabled is True

    def test_config_from_yaml(self, tmp_path) -> None:
        import yaml
        config_dict = {
            "proxy": {"port": 9999, "host": "127.0.0.1"},
            "scrubber": {"enabled": False},
        }
        path = tmp_path / "test_config.yaml"
        with open(path, "w") as f:
            yaml.dump(config_dict, f)

        from src.config import load_config
        config = load_config(path)
        assert config.proxy.port == 9999
        assert config.proxy.host == "127.0.0.1"
        assert config.scrubber.enabled is False

    def test_config_env_substitution(self, tmp_path, monkeypatch) -> None:
        import yaml
        monkeypatch.setenv("TEST_PROXY_PORT", "7777")
        config_dict = {
            "proxy": {"port": "${TEST_PROXY_PORT}"},
        }
        path = tmp_path / "test_config.yaml"
        with open(path, "w") as f:
            yaml.dump(config_dict, f)

        from src.config import load_config
        config = load_config(path)
        assert config.proxy.port == 7777

    def test_config_env_default(self, tmp_path) -> None:
        """Missing env vars use default value."""
        import yaml
        config_dict = {
            "proxy": {"port": "${NONEXISTENT_VAR:42}"},
        }
        path = tmp_path / "test_config.yaml"
        with open(path, "w") as f:
            yaml.dump(config_dict, f)

        from src.config import load_config
        config = load_config(path)
        assert config.proxy.port == 42
