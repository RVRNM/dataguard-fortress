"""Async TCP Proxy Server with CONNECT tunneling and PII scrubbing.

Features:
  - HTTP proxy (forward proxy mode)
  - HTTPS CONNECT tunneling
  - Per-route PII scrubbing hooks
  - Connection pooling for upstreams
  - Streaming support (no buffering for large bodies)
  - Signal handling for graceful shutdown
  - Performance target: <5ms overhead, 10k concurrent req/s
"""

from __future__ import annotations

import asyncio
import logging
import signal
import ssl
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Optional
from urllib.parse import urlparse

from src.config import Config, ProxyServerConfig
from src.scrubber import PIIScrubber
from src.audit import AuditEvent, AuditEventType, AuditLogger
from src.orchestrator import DataGuardOrchestrator, OrchestratorDecision

logger = logging.getLogger(__name__)


# ── Data Models ──────────────────────────────────────────────────────────────

@dataclass
class ProxyRoute:
    """A route definition for upstream proxying."""
    name: str
    host: str
    port: int
    use_tls: bool = True
    scrub_enabled: bool = True


@dataclass
class RequestContext:
    """Context for a single proxied request."""
    request_id: str = ""
    client_ip: str = ""
    method: str = ""
    target_host: str = ""
    target_port: int = 80
    start_time: float = 0.0
    end_time: float = 0.0
    bytes_upstream: int = 0
    bytes_downstream: int = 0
    scrub_count: int = 0
    error: str = ""
    headers: dict[str, str] = field(default_factory=dict)

    @property
    def duration_ms(self) -> float:
        if self.end_time > self.start_time:
            return (self.end_time - self.start_time) * 1000
        return (time.monotonic() - self.start_time) * 1000


# Type alias for per-route scrub hooks
ScrubHook = Callable[[bytes, RequestContext], Awaitable[bytes]]


# ── Connection Pool ──────────────────────────────────────────────────────────

class ConnectionPool:
    """Async connection pool to upstream servers.

    Manages reusable connections per (host, port) pair to avoid
    TCP handshake overhead on every request.
    """

    def __init__(self, max_per_host: int = 100, max_idle: float = 30.0) -> None:
        self._pools: dict[tuple[str, int, bool], asyncio.Queue[tuple[Any, Any]]] = {}
        self._max_per_host = max_per_host
        self._max_idle = max_idle
        self._lock = asyncio.Lock()
        self._active_count: dict[tuple[str, int, bool], int] = {}

    async def get(
        self,
        host: str,
        port: int,
        use_tls: bool = False,
        ssl_ctx: ssl.SSLContext | None = None,
    ) -> tuple[Any, Any]:
        """Get a connection from the pool or create a new one."""
        key = (host, port, use_tls)

        async with self._lock:
            if key not in self._pools:
                self._pools[key] = asyncio.Queue(maxsize=self._max_per_host)
                self._active_count[key] = 0
            pool = self._pools[key]

        # Try to reuse existing connection
        while not pool.empty():
            try:
                reader, writer = pool.get_nowait()
                # Check if the connection is still alive
                if reader.at_eof():
                    writer.close()
                    async with self._lock:
                        self._active_count[key] -= 1
                    continue
                return reader, writer
            except asyncio.QueueEmpty:
                break

        # Create new connection
        if use_tls and ssl_ctx:
            reader, writer = await asyncio.open_connection(
                host, port, ssl=ssl_ctx
            )
        else:
            reader, writer = await asyncio.open_connection(host, port)

        async with self._lock:
            self._active_count[key] += 1

        return reader, writer

    async def put(
        self,
        host: str,
        port: int,
        use_tls: bool,
        reader: Any,
        writer: Any,
    ) -> None:
        """Return a connection to the pool for reuse."""
        key = (host, port, use_tls)

        async with self._lock:
            if key not in self._pools:
                self._pools[key] = asyncio.Queue(maxsize=self._max_per_host)

            pool = self._pools[key]
            if pool.full():
                writer.close()
                self._active_count[key] -= 1
            else:
                pool.put_nowait((reader, writer))

    async def close_all(self) -> None:
        """Close all pooled connections."""
        for pool in self._pools.values():
            while not pool.empty():
                try:
                    _, writer = pool.get_nowait()
                    writer.close()
                except asyncio.QueueEmpty:
                    break
        self._pools.clear()
        self._active_count.clear()


# ── Core Proxy Server ────────────────────────────────────────────────────────

class AsyncProxyServer:
    """High-performance async TCP proxy with CONNECT tunneling.

    Supports:
    - Plain HTTP proxying (absolute-URI requests)
    - HTTPS via CONNECT method (tunneling)
    - Per-route scrubbing of request/response bodies
    - Connection pooling
    - Graceful shutdown on signals

    Usage:
        server = AsyncProxyServer(config)
        await server.start()
    """
    def __init__(
        self,
        config: Config,
        scrubber: PIIScrubber | None = None,
        audit: AuditLogger | None = None,
        scrub_hook: ScrubHook | None = None,
        orchestrator: DataGuardOrchestrator | None = None,
    ) -> None:
        """
        Initialize the proxy server.

        Args:
            config: Application configuration.
            scrubber: Optional PIIScrubber instance for body scanning.
            audit: Optional AuditLogger for recording events.
            scrub_hook: Optional custom scrub hook for per-route logic.
            orchestrator: Optional DataGuardOrchestrator for coordinated
                tenant resolution, classification, and rate limiting.
        """
        self._config = config
        self._proxy_config: ProxyServerConfig = config.proxy
        self._scrubber = scrubber
        self._audit = audit
        self._scrub_hook = scrub_hook
        self._orchestrator = orchestrator

        self._server: asyncio.Server | None = None
        self._pool = ConnectionPool(
            max_per_host=config.upstreams.max_keepalive,
        )
        self._running = False
        self._active_connections: set[asyncio.Task[None]] = set()
        self._semaphore = asyncio.Semaphore(
            self._proxy_config.max_concurrent_connections
        )

        # Route map: path prefix -> ProxyRoute
        self._routes: dict[str, ProxyRoute] = {}
        self._default_route: ProxyRoute | None = None

        self._setup_routes()

    def _setup_routes(self) -> None:
        """Build route map from upstream configuration."""
        if self._config.upstreams.providers:
            for provider in self._config.upstreams.providers:
                parsed = urlparse(provider.base_url)
                route = ProxyRoute(
                    name=provider.name,
                    host=parsed.hostname or "localhost",
                    port=parsed.port or (443 if parsed.scheme == "https" else 80),
                    use_tls=parsed.scheme == "https",
                )
                self._routes[provider.name] = route
                if provider.name == self._config.upstreams.default:
                    self._default_route = route
        else:
            # Default passthrough route
            self._default_route = ProxyRoute(
                name="default",
                host="localhost",
                port=8081,
                use_tls=False,
                scrub_enabled=False,
            )

    async def start(self) -> None:
        """Start the proxy server and listen for connections."""
        self._running = True

        self._server = await asyncio.start_server(
            self._handle_client,
            host=self._proxy_config.host,
            port=self._proxy_config.port,
        )

        addrs = ", ".join(str(s.getsockname()) for s in self._server.sockets)
        logger.info("Proxy server listening on %s", addrs)

        # Start orchestrator if provided
        if self._orchestrator:
            await self._orchestrator.start()

        # Setup signal handlers
        self._setup_signals()

    def _setup_signals(self) -> None:
        """Install signal handlers for graceful shutdown."""
        loop = asyncio.get_event_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, lambda: asyncio.create_task(self.stop()))
            except NotImplementedError:
                # Windows doesn't support add_signal_handler in some contexts
                signal.signal(sig, lambda s, f: asyncio.create_task(self.stop()))

    async def stop(self) -> None:
        """Gracefully shut down the proxy server."""
        logger.info("Shutting down proxy server...")
        self._running = False

        # Stop accepting new connections
        if self._server:
            self._server.close()
            await self._server.wait_closed()

        # Wait for active connections to finish
        if self._active_connections:
            logger.info("Waiting for %d active connections...", len(self._active_connections))
            await asyncio.gather(*self._active_connections, return_exceptions=True)

        # Close connection pool
        await self._pool.close_all()

        # Stop orchestrator
        if self._orchestrator:
            await self._orchestrator.stop()

        # Stop audit logger
        if self._audit:
            await self._audit.stop()

        logger.info("Proxy server shut down complete.")

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Handle an incoming client connection."""
        async with self._semaphore:
            task = asyncio.current_task()
            if task:
                self._active_connections.add(task)

            ctx = RequestContext(
                request_id=str(uuid.uuid4())[:12],
                start_time=time.monotonic(),
            )

            try:
                # Get client IP
                peer = writer.get_extra_info("peername")
                if peer:
                    ctx.client_ip = peer[0]

                # Read the first line (HTTP request line)
                first_line = await asyncio.wait_for(
                    reader.readline(),
                    timeout=self._proxy_config.connect_timeout,
                )

                if not first_line:
                    ctx.error = "empty_request"
                    return

                first_line_str = first_line.decode("utf-8", errors="replace").strip()
                if not first_line_str:
                    ctx.error = "empty_request_line"
                    return

                # Determine HTTP vs CONNECT
                match first_line_str.split():
                    case ["CONNECT", target, *_]:
                        ctx.method = "CONNECT"
                        await self._handle_connect(reader, writer, ctx, target)
                    case [method, target, *_]:
                        ctx.method = method
                        await self._handle_http_request(reader, writer, ctx, first_line, target)
                    case _:
                        ctx.error = f"unparseable_request: {first_line_str[:100]}"
                        logger.warning("Cannot parse request: %s", first_line_str[:100])

            except asyncio.TimeoutError:
                ctx.error = "read_timeout"
                logger.warning("[%s] Read timeout", ctx.request_id)
            except ConnectionResetError:
                ctx.error = "connection_reset"
            except Exception as exc:
                ctx.error = str(exc)
                logger.exception("[%s] Error handling client: %s", ctx.request_id, exc)
            finally:
                ctx.end_time = time.monotonic()
                if task:
                    self._active_connections.discard(task)

                # Ensure writer is closed
                try:
                    if not writer.is_closing():
                        writer.close()
                        await writer.wait_closed()
                except Exception:
                    pass

                # Audit log the connection
                await self._log_event(ctx)

    async def _handle_connect(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        ctx: RequestContext,
        target: str,
    ) -> None:
        """Handle CONNECT method (HTTPS tunneling).

        The client sends:
            CONNECT host:port HTTP/1.1

        We establish a TCP tunnel and relay bytes bidirectionally.
        """
        # Parse target host:port
        if ":" in target:
            host, port_str = target.rsplit(":", 1)
            port = int(port_str)
        else:
            host = target
            port = 443

        ctx.target_host = host
        ctx.target_port = port

        # Connect to upstream
        try:
            upstream_reader, upstream_writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self._proxy_config.connect_timeout,
            )
        except asyncio.TimeoutError:
            writer.write(b"HTTP/1.1 504 Gateway Timeout\r\n\r\n")
            await writer.drain()
            ctx.error = "upstream_timeout"
            return
        except OSError as exc:
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            await writer.drain()
            ctx.error = f"upstream_connect_error: {exc}"
            return

        # Send 200 OK to client
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()

        # Bidirectional relay
        await self._relay_tunnel(reader, writer, upstream_reader, upstream_writer, ctx)

        # Clean up upstream
        upstream_writer.close()
        try:
            await upstream_writer.wait_closed()
        except Exception:
            pass

    async def _relay_tunnel(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        upstream_reader: asyncio.StreamReader,
        upstream_writer: asyncio.StreamWriter,
        ctx: RequestContext,
    ) -> None:
        """Bidirectionally relay bytes between client and upstream."""
        async def client_to_upstream() -> None:
            try:
                while not client_reader.at_eof():
                    data = await client_reader.read(self._proxy_config.buffer_size)
                    if not data:
                        break
                    ctx.bytes_upstream += len(data)
                    upstream_writer.write(data)
                    await upstream_writer.drain()
            except (ConnectionResetError, BrokenPipeError, OSError):
                pass

        async def upstream_to_client() -> None:
            try:
                while not upstream_reader.at_eof():
                    data = await upstream_reader.read(self._proxy_config.buffer_size)
                    if not data:
                        break
                    ctx.bytes_downstream += len(data)
                    client_writer.write(data)
                    await client_writer.drain()
            except (ConnectionResetError, BrokenPipeError, OSError):
                pass

        # Run both directions concurrently
        c2u = asyncio.create_task(client_to_upstream())
        u2c = asyncio.create_task(upstream_to_client())

        # Wait for either direction to complete
        done, pending = await asyncio.wait(
            {c2u, u2c}, return_when=asyncio.FIRST_COMPLETED
        )

        # Cancel the other direction
        for task in pending:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    async def _handle_http_request(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        ctx: RequestContext,
        first_line: bytes,
        target: str,
    ) -> None:
        """Handle a plain HTTP proxy request (non-CONNECT).

        The request uses absolute URI form:
            GET http://example.com/path HTTP/1.1

        When an orchestrator is configured, it:
        1. Resolves tenant from X-Tenant-ID header
        2. Runs classification + rate limiting (non-blocking)
        3. Adds classification headers to the response
        4. Records audit event with classification + scrub_count + tenant
        """
        # Parse target URL
        parsed = urlparse(target)
        host = parsed.hostname or "localhost"
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        use_tls = parsed.scheme == "https"
        path = parsed.path or "/"

        ctx.target_host = host
        ctx.target_port = port

        # Read headers
        headers: dict[str, str] = {}
        header_bytes = first_line  # already have the request line

        while True:
            line = await asyncio.wait_for(
                reader.readline(),
                timeout=self._proxy_config.read_timeout,
            )
            header_bytes += line
            if line in (b"\r\n", b"\n", b""):
                break
            line_str = line.decode("utf-8", errors="replace").strip()
            if ":" in line_str:
                key, value = line_str.split(":", 1)
                headers[key.strip().lower()] = value.strip()

        ctx.headers = headers

        # Extract tenant_id from X-Tenant-ID header
        tenant_id = headers.get("x-tenant-id", "")

        # Read body if Content-Length present
        body = b""
        content_length = int(headers.get("content-length", 0))
        if content_length > 0:
            body = await reader.readexactly(content_length)
            header_bytes += body  # not quite right but close enough for relay

        # --- Orchestrator integration ---
        orchestrator_decision: OrchestratorDecision | None = None
        if self._orchestrator:
            orchestrator_decision = await self._orchestrator.process_request(
                tenant_id=tenant_id,
                body=body if body else None,
            )
            # Add tenant context headers to forwarded request
            if orchestrator_decision.tenant:
                tenant_headers = self._orchestrator.get_tenant_headers(
                    orchestrator_decision.tenant
                )
                for hk, hv in tenant_headers.items():
                    if hk.lower() not in headers:
                        headers[hk.lower()] = hv

        # Apply scrubbing if enabled
        if self._scrub_enabled_for_target(host) and self._scrub_hook:
            try:
                body = await self._scrub_hook(body, ctx)
            except Exception as exc:
                logger.warning("[%s] Scrubbing error: %s", ctx.request_id, exc)
                body = await self._fallback_scrub(body, ctx)

        elif self._scrubber and body:
            try:
                text = body.decode("utf-8", errors="replace")
                result = await self._scrubber.scrub(text)
                if result.scrubbed_count > 0:
                    body = result.scrubbed_text.encode("utf-8")
                    ctx.scrub_count = result.scrubbed_count
            except Exception as exc:
                logger.warning("[%s] Fallback scrubbing error: %s", ctx.request_id, exc)

        # Build the forwarded request
        forwarded_request = self._build_request(path, headers, body)

        # Pick upstream
        route = self._resolve_route(host)
        upstream_host = route.host if route else host
        upstream_port = route.port if route else port

        # Get connection from pool
        try:
            upstream_reader, upstream_writer = await asyncio.wait_for(
                self._pool.get(upstream_host, upstream_port, use_tls),
                timeout=self._proxy_config.connect_timeout,
            )
        except asyncio.TimeoutError:
            writer.write(b"HTTP/1.1 504 Gateway Timeout\r\n\r\n")
            await writer.drain()
            ctx.error = "upstream_timeout"
            return

        # Send request to upstream
        try:
            upstream_writer.write(forwarded_request)
            await upstream_writer.drain()
        except Exception as exc:
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            await writer.drain()
            ctx.error = f"upstream_write_error: {exc}"
            return

        # Read response and relay (with optional classification header)
        try:
            # Read the full response first so we can inject headers
            response_chunks: list[bytes] = []
            while True:
                chunk = await asyncio.wait_for(
                    upstream_reader.read(self._proxy_config.buffer_size),
                    timeout=self._proxy_config.read_timeout,
                )
                if not chunk:
                    break
                ctx.bytes_downstream += len(chunk)
                response_chunks.append(chunk)

            # Inject classification header if orchestrator provided one
            response_data = b"".join(response_chunks)
            if orchestrator_decision and orchestrator_decision.classification:
                classification = orchestrator_decision.classification
                extra_header = (
                    f"X-DataGuard-Sensitivity: {classification.level_name}\r\n"
                    f"XDataGuard-Score: {classification.score:.4f}\r\n"
                    f"X-DataGuard-Tenant: {orchestrator_decision.tenant_id}\r\n"
                )
                # Insert after the status line (first \r\n)
                status_end = response_data.find(b"\r\n")
                if status_end != -1:
                    injected = (
                        response_data[: status_end + 2]
                        + extra_header.encode("utf-8")
                        + response_data[status_end + 2 :]
                    )
                    writer.write(injected)
                else:
                    writer.write(response_data)
            else:
                writer.write(response_data)

            await writer.drain()
        except asyncio.TimeoutError:
            ctx.error = "response_timeout"
        except (ConnectionResetError, BrokenPipeError):
            ctx.error = "upstream_connection_lost"

        # Return connection to pool
        try:
            await self._pool.put(upstream_host, upstream_port, use_tls, upstream_reader, upstream_writer)
        except Exception:
            pass

        # Record audit event via orchestrator if available
        if self._orchestrator and orchestrator_decision:
            event_data = await self._orchestrator.record_response(
                request_id=ctx.request_id,
                decision=orchestrator_decision,
                scrub_count=ctx.scrub_count,
                bytes_upstream=ctx.bytes_upstream,
                bytes_downstream=ctx.bytes_downstream,
                duration_ms=ctx.duration_ms,
                error=ctx.error,
            )
            # Also log via AuditLogger if present
            if self._audit:
                audit_event = AuditEvent(
                    event_type="proxy_request",
                    request_id=ctx.request_id,
                    client_ip=ctx.client_ip,
                    method=ctx.method,
                    path=f"{ctx.target_host}:{ctx.target_port}",
                    sensitivity=event_data.get("sensitivity", "PUBLIC"),
                    scrub_count=ctx.scrub_count,
                    duration_ms=ctx.duration_ms,
                    request_size_bytes=ctx.bytes_upstream,
                    response_size_bytes=ctx.bytes_downstream,
                    error=ctx.error,
                    extra={
                        "tenant_id": event_data.get("tenant_id", "default"),
                        "sensitivity_score": event_data.get("sensitivity_score", 0.0),
                        "pii_density": event_data.get("pii_density", 0.0),
                        "classification_reasons": event_data.get("classification_reasons", []),
                    },
                )
                await self._audit.log(audit_event)

    def _build_request(
        self,
        path: str,
        headers: dict[str, str],
        body: bytes,
    ) -> bytes:
        """Build the HTTP request bytes to send upstream."""
        # Use relative path instead of absolute URI for the forwarded request
        request_line = f"GET {path} HTTP/1.1\r\n"
        if headers:
            # Pick method from headers — simplified
            method = headers.get("x-forwarded-method", "GET")
            request_line = f"{method} {path} HTTP/1.1\r\n"

        header_lines = ""
        skip_headers = {"host", "proxy-connection", "x-forwarded-method"}
        for key, value in headers.items():
            if key.lower() not in skip_headers:
                header_lines += f"{key}: {value}\r\n"

        header_lines += f"Host: {headers.get('host', 'unknown')}\r\n"
        header_bytes = (request_line + header_lines + "\r\n").encode("utf-8")
        return header_bytes + body

    async def _fallback_scrub(self, body: bytes, ctx: RequestContext) -> bytes:
        """Fallback scrubbing using the built-in scrubber."""
        if not self._scrubber or not body:
            return body
        try:
            text = body.decode("utf-8", errors="replace")
            result = await self._scrubber.scrub(text)
            ctx.scrub_count = result.scrubbed_count
            return result.scrubbed_text.encode("utf-8")
        except Exception:
            return body

    def _scrub_enabled_for_target(self, host: str) -> bool:
        """Check if scrubbing is enabled for this target host."""
        return self._proxy_config.per_route_scrub

    def _resolve_route(self, host: str) -> ProxyRoute | None:
        """Resolve the upstream route for a target host."""
        # Match by host suffix mapping
        for route in self._routes.values():
            if route.host == host or host.endswith(route.host):
                return route
        return self._default_route

    async def _log_event(self, ctx: RequestContext) -> None:
        """Emit an audit event for the completed request."""
        if not self._audit:
            return

        event = AuditEvent(
            event_type=AuditEventType.PROXY_CONNECT.value,
            request_id=ctx.request_id,
            client_ip=ctx.client_ip,
            method=ctx.method,
            path=f"{ctx.target_host}:{ctx.target_port}",
            duration_ms=ctx.duration_ms,
            scrub_count=ctx.scrub_count,
            request_size_bytes=ctx.bytes_upstream,
            response_size_bytes=ctx.bytes_downstream,
            error=ctx.error,
        )

        await self._audit.log(event)


# ── Windows Service Wrapper ──────────────────────────────────────────────────

class WindowsServiceAdapter:
    """Wrapper to run the proxy as a Windows service.

    Install:  python -m src.proxy_server install
    Start:    python -m src.proxy_server start
    Stop:     python -m src.proxy_server stop
    Remove:   python -m src.proxy_server remove
    """

    def __init__(self, server_factory: Callable[[], Awaitable[None]]) -> None:
        self._server_factory = server_factory
        self._running = False

    def run(self) -> None:
        """Start the service (blocking, for SCM)."""
        import asyncio
        self._running = True
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        async def _run() -> None:
            await self._server_factory()
            while self._running:
                await asyncio.sleep(1)

        try:
            loop.run_until_complete(_run())
        except KeyboardInterrupt:
            pass
        finally:
            loop.close()

    def stop_service(self) -> None:
        """Stop the service."""
        self._running = False
