"""Configuration management — YAML loading with Pydantic validation and hot-reload.

Supports:
  - Loading from YAML files
  - Environment variable substitution (${VAR_NAME})
  - Hot-reload when the config file changes (mtime-based)
  - All defaults specified in code
"""

from __future__ import annotations

import os
import re
import threading
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

# ── Pydantic Models for Config Validation ──────────────────────────────────────

class ServerConfig(BaseModel):
    """Server configuration."""
    host: str = "0.0.0.0"
    port: int = 8000
    workers: int = 4
    log_level: str = "info"
    access_log: bool = True
    max_request_size_mb: int = 10
    request_timeout: int = 30
    graceful_shutdown_timeout: int = 10


class ScrubberConfig(BaseModel):
    """PII scrubber configuration."""
    enabled: bool = True
    fail_closed: bool = True
    preserve_format: bool = True
    min_confidence: float = 0.5
    replacements: dict[str, str] = Field(default_factory=lambda: {
        "default": "[REDACTED_{TYPE}]",
        "EMAIL": "[REDACTED_EMAIL]",
        "PHONE": "[REDACTED_PHONE]",
    })


class AuditConfig(BaseModel):
    """Audit log configuration."""
    enabled: bool = True
    include_request_body: bool = True
    include_response_body: bool = False
    redact_in_log: bool = True
    log_dir: str = "./logs"
    log_filename: str = "audit.jsonl"
    max_size_mb: int = 100
    buffer_size: int = 100
    flush_interval_seconds: float = 1.0


class UpstreamProvider(BaseModel):
    """An upstream LLM provider configuration."""
    name: str
    base_url: str
    api_key: str = ""
    headers: dict[str, str] = Field(default_factory=dict)


class UpstreamsConfig(BaseModel):
    """Upstream routing configuration."""
    default: str = "openai"
    timeout: int = 60
    max_connections: int = 1000
    max_keepalive: int = 100
    providers: list[UpstreamProvider] = Field(default_factory=list)


class RateLimiterConfig(BaseModel):
    """Rate limiter configuration."""
    enabled: bool = True
    backend: str = "memory"
    rate: float = 10.0
    capacity: int = 50
    per_minute: int = 600


class EncryptorConfig(BaseModel):
    """Encryptor configuration."""
    enabled: bool = True
    provider: str = "aes_gcm"
    key_source: str = "env"
    key_env_var: str = "DG_ENCRYPTION_KEY"
    key_version: int = 1


class ProxyServerConfig(BaseModel):
    """TCP/HTTP proxy server configuration."""
    host: str = "0.0.0.0"
    port: int = 8080
    connect_timeout: float = 10.0
    read_timeout: float = 30.0
    buffer_size: int = 65536
    max_concurrent_connections: int = 10000
    enable_http_proxy: bool = True
    enable_connect_tunnel: bool = True
    per_route_scrub: bool = True


class Config(BaseModel):
    """Top-level DataGuard Fortress configuration."""
    server: ServerConfig = Field(default_factory=ServerConfig)
    scrubber: ScrubberConfig = Field(default_factory=ScrubberConfig)
    audit: AuditConfig = Field(default_factory=AuditConfig)
    upstreams: UpstreamsConfig = Field(default_factory=UpstreamsConfig)
    ratelimiter: RateLimiterConfig = Field(default_factory=RateLimiterConfig)
    encryptor: EncryptorConfig = Field(default_factory=EncryptorConfig)
    proxy: ProxyServerConfig = Field(default_factory=ProxyServerConfig)

    class Config:
        populate_by_name = True


# ── Environment Variable Substitution ─────────────────────────────────────────

_ENV_PATTERN = re.compile(r"\$\{([^}]+)\}")


def _substitute_env_vars(data: Any) -> Any:
    """Recursively substitute ${ENV_VAR} strings in a YAML-loaded structure."""
    match data:
        case str():
            def replacer(match: re.Match[str]) -> str:
                env_name = match.group(1)
                default = ""
                if ":" in env_name:
                    env_name, default = env_name.split(":", 1)
                return os.environ.get(env_name, default)
            return _ENV_PATTERN.sub(replacer, data)
        case dict():
            return {k: _substitute_env_vars(v) for k, v in data.items()}
        case list():
            return [_substitute_env_vars(item) for item in data]
        case _:
            return data


# ── Config Loading ────────────────────────────────────────────────────────────

_config_cache: dict[str, tuple[float, Config]] = {}
_cache_lock = threading.Lock()


def load_config(path: str | Path) -> Config:
    """Load and validate configuration from a YAML file.

    Environment variables in ${VAR_NAME} format are substituted.
    Results are cached by file path and mtime for performance.

    Args:
        path: Path to the YAML configuration file.

    Returns:
        Validated Config instance.

    Raises:
        FileNotFoundError: If the config file doesn't exist.
        yaml.YAMLError: If the YAML is invalid.
        pydantic.ValidationError: If config doesn't match schema.
    """
    path = Path(path).resolve()

    with _cache_lock:
        mtime = path.stat().st_mtime
        if str(path) in _config_cache:
            cached_mtime, cached_config = _config_cache[str(path)]
            if cached_mtime == mtime:
                return cached_config

    with open(path) as f:
        raw = yaml.safe_load(f) or {}

    substituted = _substitute_env_vars(raw)
    config = Config.model_validate(substituted)

    with _cache_lock:
        _config_cache[str(path)] = (mtime, config)

    return config


def reload_config(path: str | Path) -> Config:
    """Force reload configuration (ignoring cache).

    Args:
        path: Path to the YAML configuration file.

    Returns:
        Fresh Config instance.
    """
    path = Path(path).resolve()

    with _cache_lock:
        _config_cache.pop(str(path), None)

    return load_config(path)


def create_default_config(path: str | Path) -> Config:
    """Create a default configuration file.

    Args:
        path: Where to write the YAML config.

    Returns:
        The default Config instance.
    """
    config = Config()
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    # Convert to dict and write as YAML
    config_dict = config.model_dump()
    with open(path, "w") as f:
        yaml.dump(config_dict, f, default_flow_style=False, sort_keys=False)

    return config


class ConfigWatcher:
    """Watch a config file for changes and trigger hot-reload.

    Usage:
        watcher = ConfigWatcher("config/default.yaml", callback=on_reload)
        await watcher.start()
    """

    def __init__(
        self,
        path: str | Path,
        callback: None = None,
        interval: float = 5.0,
    ) -> None:
        self.path = Path(path).resolve()
        self._callback = callback
        self._interval = interval
        self._running = False

    async def start(self) -> None:
        """Start watching the config file for changes."""
        import asyncio

        self._running = True
        last_mtime = self.path.stat().st_mtime

        while self._running:
            await asyncio.sleep(self._interval)
            try:
                current_mtime = self.path.stat().st_mtime
                if current_mtime != last_mtime:
                    last_mtime = current_mtime
                    config = reload_config(self.path)
                    if self._callback:
                        if asyncio.iscoroutinefunction(self._callback):
                            await self._callback(config)
                        else:
                            self._callback(config)
            except OSError:
                pass  # File temporarily unavailable

    def stop(self) -> None:
        """Stop watching."""
        self._running = False
