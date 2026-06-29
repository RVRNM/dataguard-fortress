"""Integration tests for DataGuard Fortress proxy."""

from __future__ import annotations

import asyncio
import json
import socket
import time
from pathlib import Path
from typing import AsyncGenerator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio

from src.config import (
    AuditConfig,
    Config,
    ProxyServerConfig,
    RateLimiterConfig,
    ScrubberConfig,
    UpstreamsConfig,
    UpstreamProvider,
)
from src.proxy_server import (
    AsyncProxyServer,
    ConnectionPool,
    ProxyRoute,
    RequestContext,
)
from src.scrubber import PIIScrubber, ScrubResult
from src.audit import AuditEvent, AuditEventType, AuditLogger


@pytest.fixture
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture
async def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest_asyncio.fixture
async def upstream_server(free_port: int) -> AsyncGenerator[tuple[str, int], None]:
    def protocol_factory():
        proto = asyncio.Protocol()
        def connection_made(transport):
            pass
        def data_received(data):
            body = b'{"status": "ok", "proxied": true}'
            response = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/json\r\n"
                b"Content-Length: "
                + str(len(body)).encode()
                + b"\r\n"
                + b"\r\n"
                + body
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


class TestEndToEnd:
    @pytest.mark.asyncio
    async def test_proxy_forwards_http_request(
        self, free_port: int, upstream_server: tuple[str, int]
    ) -> None:
        config = Config(
            scrubber=ScrubberConfig(enabled=True, min_confidence=0.0, fail_closed=False),
            audit=AuditConfig(enabled=False),
            upstreams=UpstreamsConfig(
                default="test",
                providers=[
                    UpstreamProvider(
                        name="test",
                        base_url=f"http://{upstream_server[0]}:{upstream_server[1]}",
                    )
                ],
            ),
            proxy=ProxyServerConfig(
                host="127.0.0.1",
                port=free_port + 1,
                buffer_size=4096,
                max_concurrent_connections=100,
                connect_timeout=5.0,
                read_timeout=10.0,
            ),
        )

        server = AsyncProxyServer(config=config)
        await server.start()

        try:
            request = (
                f"GET http://{upstream_server[0]}:{upstream_server[1]}/test HTTP/1.1\r\n"
                f"Host: {upstream_server[0]}:{upstream_server[1]}\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: 16\r\n"
                f"\r\n"
                f'{{"hello": "world"}}'
            ).encode()

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", config.proxy.port),
                timeout=5.0,
            )

            writer.write(request)
            await writer.drain()

            response = await asyncio.wait_for(reader.read(4096), timeout=5.0)
            response_str = response.decode("utf-8", errors="replace")

            assert "200 OK" in response_str
            assert '{"status": "ok", "proxied": true}' in response_str

            writer.close()
            await writer.wait_closed()
        finally:
            await server.stop()

    @pytest.mark.asyncio
    async def test_proxy_returns_502_on_unreachable_upstream(
        self, free_port: int
    ) -> None:
        config = Config(
            scrubber=ScrubberConfig(enabled=True, min_confidence=0.0),
            audit=AuditConfig(enabled=False),
            upstreams=UpstreamsConfig(
                default="test",
                providers=[
                    UpstreamProvider(
                        name="test",
                        base_url=f"http://127.0.0.1:{free_port + 50}",
                    )
                ],
            ),
            proxy=ProxyServerConfig(
                host="127.0.0.1",
                port=free_port + 1,
                connect_timeout=1.0,
                read_timeout=2.0,
            ),
        )

        server = AsyncProxyServer(config=config)
        await server.start()

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", config.proxy.port),
                timeout=5.0,
            )

            request = (
                f"GET http://127.0.0.1:{free_port + 50}/test HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{free_port + 50}\r\n"
                f"Content-Length: 0\r\n"
                f"\r\n"
            ).encode()

            writer.write(request)
            await writer.drain()

            response = await asyncio.wait_for(reader.read(4096), timeout=10.0)
            response_str = response.decode("utf-8", errors="replace")

            assert "502" in response_str or "504" in response_str

            writer.close()
            await writer.wait_closed()
        finally:
            await server.stop()


class TestHTTPSConnect:
    @pytest.mark.asyncio
    async def test_connect_tunnel_mock(self) -> None:
        config = Config(
            scrubber=ScrubberConfig(enabled=False),
            audit=AuditConfig(enabled=False),
            proxy=ProxyServerConfig(
                host="127.0.0.1",
                port=0,
                connect_timeout=1.0,
            ),
        )

        mock_reader = AsyncMock(spec=asyncio.StreamReader)
        mock_writer = AsyncMock(spec=asyncio.StreamWriter)
        mock_reader.at_eof.return_value = False
        mock_reader.read = AsyncMock(return_value=b"")
        mock_writer.is_closing.return_value = False
        mock_writer.wait_closed = AsyncMock()

        server = AsyncProxyServer(config=config)

        client_reader = asyncio.StreamReader()
        client_writer = MagicMock(spec=asyncio.StreamWriter)
        client_writer.is_closing.return_value = False
        client_writer.write = MagicMock()
        client_writer.drain = AsyncMock()
        client_writer.wait_closed = AsyncMock()
        client_writer.get_extra_info = MagicMock(return_value=("127.0.0.1", 12345))

        client_reader.feed_data(
            b"CONNECT example.com:443 HTTP/1.1\r\n"
            b"Host: example.com:443\r\n"
            b"\r\n"
        )
        client_reader.feed_eof()

        with patch(
            "asyncio.open_connection",
            return_value=(mock_reader, mock_writer),
        ):
            ctx = RequestContext(
                request_id="test-connect",
                start_time=time.monotonic(),
            )
            await server._handle_connect(
                client_reader, client_writer, ctx, "example.com:443"
            )

        client_writer.write.assert_called_once_with(
            b"HTTP/1.1 200 Connection Established\r\n\r\n"
        )
        assert ctx.target_host == "example.com"
        assert ctx.target_port == 443

    @pytest.mark.asyncio
    async def test_connect_tunnel_timeout(self) -> None:
        config = Config(
            scrubber=ScrubberConfig(enabled=False),
            audit=AuditConfig(enabled=False),
            proxy=ProxyServerConfig(
                host="127.0.0.1",
                port=0,
                connect_timeout=0.1,
            ),
        )

        server = AsyncProxyServer(config=config)

        client_reader = asyncio.StreamReader()
        client_writer = MagicMock(spec=asyncio.StreamWriter)
        client_writer.is_closing.return_value = False
        client_writer.write = MagicMock()
        client_writer.drain = AsyncMock()
        client_writer.wait_closed = AsyncMock()
        client_writer.get_extra_info = MagicMock(return_value=("127.0.0.1", 12345))

        client_reader.feed_data(
            b"CONNECT 192.0.2.1:443 HTTP/1.1\r\n"
            b"Host: 192.0.2.1:443\r\n"
            b"\r\n"
        )
        client_reader.feed_eof()

        ctx = RequestContext(
            request_id="test-timeout",
            start_time=time.monotonic(),
        )
        await server._handle_connect(
            client_reader, client_writer, ctx, "192.0.2.1:443"
        )

        client_writer.write.assert_called_once_with(
            b"HTTP/1.1 504 Gateway Timeout\r\n\r\n"
        )
        assert ctx.error == "upstream_timeout"


class TestFailClosed:
    @pytest.mark.asyncio
    async def test_scrubber_exception_handled_gracefully(
        self, free_port: int, upstream_server: tuple[str, int]
    ) -> None:
        config = Config(
            scrubber=ScrubberConfig(enabled=True, min_confidence=0.0, fail_closed=False),
            audit=AuditConfig(enabled=False),
            upstreams=UpstreamsConfig(
                default="test",
                providers=[
                    UpstreamProvider(
                        name="test",
                        base_url=f"http://{upstream_server[0]}:{upstream_server[1]}",
                    )
                ],
            ),
            proxy=ProxyServerConfig(
                host="127.0.0.1",
                port=free_port + 1,
                buffer_size=4096,
                max_concurrent_connections=100,
                connect_timeout=5.0,
                read_timeout=10.0,
            ),
        )

        failing_scrubber = AsyncMock(spec=PIIScrubber)
        failing_scrubber.scrub = AsyncMock(side_effect=RuntimeError("Scrubber failed!"))

        server = AsyncProxyServer(config=config, scrubber=failing_scrubber)
        await server.start()

        try:
            request = (
                f"GET http://{upstream_server[0]}:{upstream_server[1]}/test HTTP/1.1\r\n"
                f"Host: {upstream_server[0]}:{upstream_server[1]}\r\n"
                f"Content-Length: 0\r\n"
                f"\r\n"
            ).encode()

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", config.proxy.port),
                timeout=5.0,
            )

            writer.write(request)
            await writer.drain()

            response = await asyncio.wait_for(reader.read(4096), timeout=5.0)
            response_str = response.decode("utf-8", errors="replace")
            assert response_str

            writer.close()
            await writer.wait_closed()
        finally:
            await server.stop()

    def test_fail_closed_config_flag(self) -> None:
        config = Config(
            scrubber=ScrubberConfig(enabled=True, min_confidence=0.0, fail_closed=True),
        )
        assert config.scrubber.fail_closed is True

    @pytest.mark.asyncio
    async def test_fallback_scrub_used_on_hook_failure(self) -> None:
        config = Config(
            scrubber=ScrubberConfig(enabled=True, min_confidence=0.0),
            audit=AuditConfig(enabled=False),
            proxy=ProxyServerConfig(host="127.0.0.1", port=0),
        )

        server = AsyncProxyServer(config=config)
        real_scrubber = PIIScrubber(min_confidence=0.0)
        server._scrubber = real_scrubber

        body = b"email: test@example.com"
        ctx = RequestContext(request_id="test-fallback")

        result = await server._fallback_scrub(body, ctx)
        assert b"[REDACTED_EMAIL]" in result


class TestScrubIntegration:
    @pytest.mark.asyncio
    async def test_pii_in_request_body_scrubbed(
        self, free_port: int, upstream_server: tuple[str, int]
    ) -> None:
        config = Config(
            scrubber=ScrubberConfig(enabled=True, min_confidence=0.0),
            audit=AuditConfig(enabled=False),
            upstreams=UpstreamsConfig(
                default="test",
                providers=[
                    UpstreamProvider(
                        name="test",
                        base_url=f"http://{upstream_server[0]}:{upstream_server[1]}",
                    )
                ],
            ),
            proxy=ProxyServerConfig(
                host="127.0.0.1",
                port=free_port + 1,
                buffer_size=4096,
                max_concurrent_connections=100,
                connect_timeout=5.0,
                read_timeout=10.0,
            ),
        )

        scrubber = PIIScrubber(min_confidence=0.0)
        server = AsyncProxyServer(config=config, scrubber=scrubber)
        await server.start()

        try:
            pii_body = (
                '{"user": "alice@example.com", "phone": "555-123-4567", '
                '"ssn": "123-45-6789", "note": "hello"}'
            ).encode()

            request = (
                f"POST http://{upstream_server[0]}:{upstream_server[1]}/api HTTP/1.1\r\n"
                f"Host: {upstream_server[0]}:{upstream_server[1]}\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(pii_body)}\r\n"
                f"\r\n"
            ).encode() + pii_body

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", config.proxy.port),
                timeout=5.0,
            )

            writer.write(request)
            await writer.drain()

            response = await asyncio.wait_for(reader.read(4096), timeout=5.0)
            assert len(response) > 0
            assert b"200 OK" in response

            writer.close()
            await writer.wait_closed()
        finally:
            await server.stop()

    @pytest.mark.asyncio
    async def test_scrub_count_tracked(
        self, free_port: int, upstream_server: tuple[str, int]
    ) -> None:
        config = Config(
            scrubber=ScrubberConfig(enabled=True, min_confidence=0.0),
            audit=AuditConfig(enabled=False),
            upstreams=UpstreamsConfig(
                default="test",
                providers=[
                    UpstreamProvider(
                        name="test",
                        base_url=f"http://{upstream_server[0]}:{upstream_server[1]}",
                    )
                ],
            ),
            proxy=ProxyServerConfig(
                host="127.0.0.1",
                port=free_port + 1,
                buffer_size=4096,
                max_concurrent_connections=100,
                connect_timeout=5.0,
                read_timeout=10.0,
            ),
        )

        scrubber = PIIScrubber(min_confidence=0.0)
        server = AsyncProxyServer(config=config, scrubber=scrubber)
        await server.start()

        try:
            pii_body = b'{"email": "bob@example.com"}'

            request = (
                f"POST http://{upstream_server[0]}:{upstream_server[1]}/api HTTP/1.1\r\n"
                f"Host: {upstream_server[0]}:{upstream_server[1]}\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(pii_body)}\r\n"
                f"\r\n"
            ).encode() + pii_body

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", config.proxy.port),
                timeout=5.0,
            )

            writer.write(request)
            await writer.drain()

            response = await asyncio.wait_for(reader.read(4096), timeout=5.0)
            assert len(response) > 0

            writer.close()
            await writer.wait_closed()
        finally:
            await server.stop()


class TestRateLimiter:
    def test_rate_limiter_config_defaults(self) -> None:
        config = RateLimiterConfig()
        assert config.enabled is True
        assert config.rate == 10.0
        assert config.capacity == 50

    def test_rate_limiter_config_custom(self) -> None:
        config = RateLimiterConfig(enabled=True, rate=5.0, capacity=10, per_minute=100)
        assert config.rate == 5.0
        assert config.capacity == 10
        assert config.per_minute == 100

    @pytest.mark.asyncio
    async def test_rate_limiter_tracks_requests(self) -> None:
        config = Config(
            ratelimiter=RateLimiterConfig(enabled=True, rate=2.0, capacity=3),
        )
        assert config.ratelimiter.enabled is True
        assert config.ratelimiter.rate == 2.0
        assert config.ratelimiter.capacity == 3

    @pytest.mark.asyncio
    async def test_rate_limiter_disabled(self) -> None:
        config = Config(ratelimiter=RateLimiterConfig(enabled=False))
        assert config.ratelimiter.enabled is False


class TestPresetCount:
    def test_52_presets_loaded(self) -> None:
        scrubber = PIIScrubber(min_confidence=0.0)
        assert scrubber.preset_count >= 52

    def test_preset_names_available(self) -> None:
        scrubber = PIIScrubber(min_confidence=0.0)
        names = scrubber.get_preset_names()
        assert len(names) >= 52
        assert "email" in names
        assert "ssn" in names
        assert "credit_card_visa" in names

    def test_preset_summary_by_entity_type(self) -> None:
        scrubber = PIIScrubber(min_confidence=0.0)
        summary = scrubber.get_preset_summary()
        assert "EMAIL" in summary
        assert "CREDIT_CARD" in summary
        assert summary["CREDIT_CARD"] >= 4

    def test_presets_filtered_by_confidence(self) -> None:
        scrubber_low = PIIScrubber(min_confidence=0.0)
        scrubber_high = PIIScrubber(min_confidence=0.9)
        assert scrubber_high.preset_count < scrubber_low.preset_count
        assert scrubber_high.preset_count > 0


class TestAuditWritten:
    @pytest.mark.asyncio
    async def test_audit_events_written_after_request(
        self, free_port: int, upstream_server: tuple[str, int], tmp_path: Path
    ) -> None:
        config = Config(
            scrubber=ScrubberConfig(enabled=True, min_confidence=0.0),
            audit=AuditConfig(
                enabled=True,
                log_dir=str(tmp_path / "audit"),
                buffer_size=1,
                flush_interval_seconds=0.1,
            ),
            upstreams=UpstreamsConfig(
                default="test",
                providers=[
                    UpstreamProvider(
                        name="test",
                        base_url=f"http://{upstream_server[0]}:{upstream_server[1]}",
                    )
                ],
            ),
            proxy=ProxyServerConfig(
                host="127.0.0.1",
                port=free_port + 1,
                buffer_size=4096,
                max_concurrent_connections=100,
                connect_timeout=5.0,
                read_timeout=10.0,
            ),
        )

        audit_logger = AuditLogger(config=config.audit)
        await audit_logger.start()

        server = AsyncProxyServer(config=config, audit=audit_logger)
        await server.start()

        try:
            request = (
                f"GET http://{upstream_server[0]}:{upstream_server[1]}/test HTTP/1.1\r\n"
                f"Host: {upstream_server[0]}:{upstream_server[1]}\r\n"
                f"Content-Length: 0\r\n"
                f"\r\n"
            ).encode()

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", config.proxy.port),
                timeout=5.0,
            )

            writer.write(request)
            await writer.drain()

            response = await asyncio.wait_for(reader.read(4096), timeout=5.0)
            assert len(response) > 0

            writer.close()
            await writer.wait_closed()
        finally:
            await server.stop()

        await asyncio.sleep(1.0)

        audit_file = tmp_path / "audit" / "audit.jsonl"
        assert audit_file.exists(), f"Audit file not found at {audit_file}"

        content = audit_file.read_text(encoding="utf-8")
        lines = [line for line in content.strip().split("\n") if line.strip()]
        assert len(lines) >= 1, "Expected at least one audit entry"

        first_event = json.loads(lines[0])
        assert "event_type" in first_event
        assert "request_id" in first_event

    @pytest.mark.asyncio
    async def test_audit_disabled_no_file_created(
        self, free_port: int, tmp_path: Path
    ) -> None:
        config = Config(
            scrubber=ScrubberConfig(enabled=False),
            audit=AuditConfig(enabled=False, log_dir=str(tmp_path / "audit_disabled")),
            upstreams=UpstreamsConfig(default="test"),
            proxy=ProxyServerConfig(host="127.0.0.1", port=free_port + 1),
        )

        audit_logger = AuditLogger(config=config.audit)
        await audit_logger.start()
        await audit_logger.stop()

        audit_dir = tmp_path / "audit_disabled"
        if audit_dir.exists():
            files = list(audit_dir.iterdir())
            assert len(files) == 0


class TestBenchmark:
    @pytest.mark.asyncio
    async def test_benchmark_scrub_1kb(self, benchmark) -> None:
        scrubber = PIIScrubber(min_confidence=0.0)
        text = (
            "User profile: email=john@example.com, phone=555-123-4567. "
            "SSN: 123-45-6789. Card: 4111-1111-1111-1111. "
            "API key: sk-abcdefghijklmnopqrstuvwxyz123456. "
            "IP: 192.168.1.100. Contact: admin@company.com. "
        ) * 10

        async def run():
            return await scrubber.scrub(text)

        result = benchmark(run)
        assert result is not None

    @pytest.mark.asyncio
    async def test_benchmark_scrub_10kb(self, benchmark) -> None:
        scrubber = PIIScrubber(min_confidence=0.0)
        text = (
            "User profile: email=john@example.com, phone=555-123-4567. "
            "SSN: 123-45-6789. Card: 4111-1111-1111-1111. "
            "API key: sk-abcdefghijklmnopqrstuvwxyz123456. "
            "AWS: AKIAIOSFODNN7EXAMPLE. Contact: admin@company.com. "
        ) * 100

        async def run():
            return await scrubber.scrub(text)

        result = benchmark(run)
        assert result is not None

    @pytest.mark.asyncio
    async def test_benchmark_scrub_100kb(self, benchmark) -> None:
        scrubber = PIIScrubber(min_confidence=0.0)
        text = (
            "User profile: email=john@example.com, phone=555-123-4567. "
            "SSN: 123-45-6789. Card: 4111-1111-1111-1111. "
            "API key: sk-abcdefghijklmnopqrstuvwxyz123456. "
            "AWS: AKIAIOSFODNN7EXAMPLE. Contact: admin@company.com. "
            "GitHub: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef01. "
        ) * 1000

        async def run():
            return await scrubber.scrub(text)

        result = benchmark(run)
        assert result is not None


class TestRequestContext:
    def test_duration_calculation(self) -> None:
        ctx = RequestContext(start_time=100.0, end_time=105.5)
        assert ctx.duration_ms == 5500.0

    def test_duration_running(self) -> None:
        ctx = RequestContext(start_time=time.monotonic())
        assert ctx.duration_ms < 1000

    def test_default_values(self) -> None:
        ctx = RequestContext()
        assert ctx.scrub_count == 0
        assert ctx.bytes_upstream == 0
        assert ctx.error == ""


class TestConnectionPool:
    @pytest.mark.asyncio
    async def test_close_all(self) -> None:
        pool = ConnectionPool()
        await pool.close_all()

    @pytest.mark.asyncio
    async def test_get_with_mocked_connection(self) -> None:
        pool = ConnectionPool()

        mock_reader = AsyncMock(spec=asyncio.StreamReader)
        mock_writer = AsyncMock(spec=asyncio.StreamWriter)
        mock_reader.at_eof.return_value = False

        with patch(
            "asyncio.open_connection",
            return_value=(mock_reader, mock_writer),
        ):
            reader, writer = await pool.get("127.0.0.1", 9999, use_tls=False)
            assert reader is not None
            assert writer is not None

        await pool.close_all()


class TestProxyRoutes:
    def test_default_route_setup(self) -> None:
        config = Config()
        server = AsyncProxyServer(config=config)
        assert server._default_route is not None

    def test_routes_from_upstreams(self) -> None:
        config = Config(
            upstreams=UpstreamsConfig(
                default="openai",
                providers=[
                    UpstreamProvider(name="openai", base_url="https://api.openai.com/v1"),
                    UpstreamProvider(name="anthropic", base_url="https://api.anthropic.com/v1"),
                ],
            ),
        )
        server = AsyncProxyServer(config=config)
        assert "openai" in server._routes
        assert "anthropic" in server._routes
        assert server._default_route is not None
        assert server._default_route.name == "openai"

    def test_resolve_route_fallback(self) -> None:
        config = Config()
        server = AsyncProxyServer(config=config)
        route = server._resolve_route("unknown-host.example.com")
        assert route == server._default_route
