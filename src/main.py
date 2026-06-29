"""DataGuard Fortress — CLI entry point."""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import signal
import sys

from src import __version__
from src.config import Config, create_default_config, load_config
from src.proxy_server import AsyncProxyServer
from src.scrubber import PIIScrubber


def build_argument_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser with strict, safe choices."""
    parser = argparse.ArgumentParser(
        prog="dataguard",
        description="DataGuard Fortress — Privacy proxy for AI agents",
        epilog="Example: dataguard --port 8080 --config config.yaml",
    )

    parser.add_argument(
        "--port", "-p",
        type=int,
        default=8080,
        choices=[v for v in range(1024, 65536)],  # Valid port range only
        help="Port to listen on (default: 8080)",
    )
    parser.add_argument(
        "--config", "-c",
        type=str,
        default="config.yaml",
        help="Path to YAML configuration file (default: config.yaml)",
    )
    parser.add_argument(
        "--log-level", "-l",
        type=str,
        default="info",
        choices=["debug", "info", "warning", "error", "critical"],  # Strict allowlist
        help="Logging level (default: info)",
    )
    parser.add_argument(
        "--host",
        type=str,
        default="0.0.0.0",
        choices=["0.0.0.0", "127.0.0.1", "localhost"],  # Strict allowlist
        help="Host to bind to (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--generate-config",
        type=str,
        metavar="PATH",
        help="Generate a default configuration file at PATH and exit",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        help="Number of worker processes (default: 1)",
    )

    return parser


async def run_server(args: argparse.Namespace) -> None:
    """Main async entry point."""
    # Generate config and exit
    if args.generate_config:
        create_default_config(args.generate_config)
        print(f"✅ Default config written to {args.generate_config}")
        return

    # Load config
    config = load_config(args.config) if os.path.exists(args.config) else Config()

    # Override CLI args into proxysafe bounds
    config.proxy.host = args.host
    config.proxy.port = args.port
    if args.workers > 1:
        config.server.workers = args.workers

    setup_logging(args.log_level)

    # Create components
    scrubber = PIIScrubber(
        min_confidence=config.scrubber.min_confidence,
    )

    audit = AuditLogger(config=config) if config.audit.enabled else None

    # Override port from config if set
    config.proxy.port = config.proxy.port

    # Create server
    server = AsyncProxyServer(
        config=config,
        scrubber=scrubber,
        audit=audit,
    )

    # Signal handlers
    asyncio.get_event_loop()

    def _shutdown(signum, frame):
        logging.getLogger("dataguard.main").info(f"Signal {signum} received, shutting down...")
        asyncio.create_task(server.stop())

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    # Start server
    logging.getLogger("dataguard").info(
        "Starting DataGuard Fortress v%s on %s:%d",
        __version__,
        config.proxy.host,
        config.proxy.port,
    )

    try:
        await server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        await server.stop()


def setup_logging(level: str = "info") -> None:
    """Configure application-wide logging."""
    level_upper = level.upper()
    numeric_level = logging.getLevelName(level_upper)
    if not isinstance(numeric_level, int):
        numeric_level = logging.INFO

    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        stream=sys.stderr,
    )


def main():
    parser = build_argument_parser()
    args = parser.parse_args()

    asyncio.run(run_server(args))


if __name__ == "__main__":
    main()
