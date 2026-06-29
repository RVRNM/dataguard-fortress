"""DataGuard Fortress — A high-performance privacy proxy for AI agents.

This package provides PII scrubbing, classification, encryption,
rate limiting, and audit logging for AI agent traffic.
"""

__version__ = "0.1.0"
__author__ = "DataGuard Contributors"

from src.scrubber import PIIScrubber, ScrubResult
from src.config import Config, load_config
from src.audit import AuditEvent, AuditLogger

__all__ = [
    "PIIScrubber",
    "ScrubResult",
    "Config",
    "load_config",
    "AuditEvent",
    "AuditLogger",
    "__version__",
]
