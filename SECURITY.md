# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.3.x   | ✅ |
| 0.2.x   | ✅ |
| < 0.2   | ❌ |

## Reporting a Vulnerability

Please report security issues to: security@dataguard-fortress.dev

We acknowledge reports within 48 hours and provide a fix timeline within 7 days.

## Known Security Findings

### SkillSpector Scan Results (2026-06-29)

| Finding | Severity | Status | Notes |
|---------|----------|--------|-------|
| Session Persistence (asyncio background tasks) | MEDIUM | � Benign | Required for tenant hot-reload; configurable |
| Context Window Stuffing (HTML) | MEDIUM | 🟢 Benign | Static UI text, no user input injection |
| Tool Parameter Abuse | HIGH | � **Fixed** | `getattr(logging, ...)` replaced by `logging.getLevelName()` |
| Dynamic Import (`__import__`) | MEDIUM | 🟢 **Fixed** | Replaced by static `from ... import ...` |

### Data Handling

- **All PII scrubbing is local** — no data leaves your network
- **Audit logs stay on your disk external telemetry
- **No external network calls** in the proxy itself
- **Encryption keys** should be provided via environment variables only
- **Tenant isolation**: per-tenant configs with separate rate limits, scrubbers, and upstreams

### Dependencies

All dependencies are pinned in `pyproject.toml`. Run `pip-audit` periodically:

```bash
pip-audit
```

### Hardening Recommendations

1. Run the proxy as a non-root user (default in Docker)
2. Set `DG_ENCRYPTION_KEY` via environment variable (not in config file)
3. Enable `fail_closed: true` in production scrubber config
4. Restrict `tenants/` directory permissions to `0600`
5. Use the dashboard only behind authentication (no auth built-in — use reverse proxy)

## Compliance

- **GDPR**: All processing happens on your infrastructure. Data minimization by default.
- **SOC 2**: Audit log trail supports compliance requirements. Hash chain integrity is append-only.
- **HIPAA**: PII scrubbing includes medical record numbers, health insurance IDs
