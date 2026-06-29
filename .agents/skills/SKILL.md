---
name: dataguard-fortress
version: "1.0.0"
description: "Complete operational skill for DataGuard Fortress — self-hosted privacy proxy with PII scrubbing, sensitivity classification, rate limiting, multi-tenant policies, and audit logging. Compatible with all AI coding agents (Claude Code, Codex CLI, Cursor, Aider, Continue, Cline, OpenCode, Hermes Agent, and any SKILL.md-compatible agent)."
tags: [privacy, proxy, pii, scrubbing, ai-agent, security, audit, multi-tenant, rate-limiter, classifier, llm, self-hosted, gdpr, compliance]
metadata:
  author: "DataGuard Contributors"
  license: "Apache-2.0"
  platforms: [windows, linux, macos]
  min_python: "3.11"
  repo: "https://github.com/RVRNM/dataguard-fortress"
use_when:
  - User says "dataguard" or "data guard" or "privacy proxy" or "PII scrub" or "LLM privacy"
  - User wants to intercept and sanitize API calls before they reach LLM providers
  - User needs GDPR-compliant LLM usage or audit logging for AI compliance
  - User asks about per-tenant proxy policies or rate limiting for AI agents
  - User reports a DataGuard Fortress configuration or runtime issue
  - User wants to classify data sensitivity before LLM API calls
---

# DataGuard Fortress

Self-hosted privacy proxy for AI agents. Scrubs PII inline, classifies sensitivity, rate-limits per tenant, and audits every request — so sensitive data never reaches OpenAI, Anthropic, Google, or any upstream LLM provider.

## When to Use

Trigger this skill when:
- User mentions any trigger keyword above
- User wants to add PII scrubbing to their AI agent stack
- User needs to set up multi-tenant proxy policies
- User asks about rate limiting for AI traffic
- User wants audit logging for AI compliance (GDPR, SOC 2, HIPAA)
- User reports a DataGuard Fortress issue

## Prerequisites

- Python 3.11+
- pip or uv
- (Optional) Docker + docker-compose
- (Optional) Redis (for shared rate limiting across instances)

## Install

### Fresh install
```bash
git clone https://github.com/RVRNM/dataguard-fortress.git
cd dataguard-fortress
python3 -m venv .venv
source .venv/bin/activate  # Linux/macOS
# .venv\Scripts\activate   # Windows
pip install -e ".[prod]"
```

Verify: `dataguard --version` should print `DataGuard Fortress X.Y.Z`

### Quick Start

```bash
# 1. Generate default config
dataguard --generate-config config.yaml

# 2. Start proxy
dataguard --port 8080

# 3. Redirect your AI agent traffic
export HTTP_PROXY=http://localhost:8080
export HTTPS_PROXY=http://localhost:8080

# 4. Verify
curl -x http://localhost:8080 http://httpbin.org/get

# 5. Open dashboard
open http://localhost:8080/
```

### Docker (recommended for production)
```bash
docker-compose up -d --build
```

## Architecture

```
AI Agent → DataGuard Proxy (localhost:8080) → LLM Provider
              │
              ├─ Tenant Resolution   → per-tenant YAML policy
              ├─ Rate Limiting       → token bucket + sliding window
              ├─ Sensitivity Class.  → PUBLIC/INTERNAL/CONFIDENTIAL/RESTRICTED
              ├─ PII Scrubbing       → 52 regex presets (emails, SSN, CCs, API keys...)
              ├─ Audit Logger        → JSONL append-only + hash chain
              └─ (opt) Encryption    → AES-GCM for payloads at rest
```

## Configuration

### Minimal `config.yaml`
```yaml
proxy:
  host: "127.0.0.1"
  port: 8080
  max_concurrent_connections: 10000
  buffer_size: 65536

scrubber:
  enabled: true
  fail_closed: true
  min_confidence: 0.5

ratelimiter:
  enabled: true
  rate: 10.0
  capacity: 50
  per_minute: 600

audit:
  enabled: true
  log_dir: ./logs
  log_filename: audit.jsonl
  max_size_mb: 100

tenants:
  tenants_dir: ./tenants
  hot_reload: true
  reload_interval: 60
```

### Multi-tenant setup

Create per-tenant YAML files in `tenants/`:

```yaml
# tenants/acme-corp.yaml
tenant_id: acme-corp
name: Acme Corporation
rate_limit:
  requests_per_second: 20.0
  burst_size: 100
  max_concurrent: 50
  window_seconds: 120
scrubber:
  fail_closed: true
  extra_presets:
    - name: employee_id
      pattern: '\bEMP-[0-9]{6}\b'
      entity_type: EMPLOYEE_ID
      replacement: "[REDACTED]"
      confidence: 0.95
upstream:
  allowed_hosts:
    - api.openai.com
    - api.anthropic.com
  blocked_hosts:
    - "*.evil.com"
```

Tenant is selected via `X-Tenant-ID` header or defaults to "default".

### 52 Built-in PII Presets

Covers: email (RFC), phone (FR/US/intl), SSN, credit cards (Visa/MC/Amex/Discover),
API keys (OpenAI, Anthropic, AWS, GCP, GitHub, Stripe, Slack, Twilio, Firebase, Square),
cryptocurrency (BTC, ETH), medical (MRN, health insurance ID, NPI, prescription, ICD),
government (passport, driver license, ITIN, EIN, IBAN, SWIFT), network (IPv4/IPv6, MAC,
URL with credentials), JWT, SSH keys, DB URLs, bearer tokens, dates of birth, and more.

### Custom PII presets

```yaml
scrubber:
  extra_presets:
    - name: project_code
      pattern: '\bPRJ-[A-Z]{3}-[0-9]{4}\b'
      entity_type: INTERNAL_PROJECT_CODE
      replacement: "[REDACTED_PROJECT]"
      confidence: 0.95
```

## Key Commands

| Command | Description |
|---------|-------------|
| `dataguard --port 8080` | Start proxy on port 8080 |
| `dataguard --config config.yaml` | Use custom config |
| `dataguard --generate-config config.yaml` | Generate default config |
| `dataguard --log-level debug` | Verbose logging |
| `dataguard --log-level warning` | Only warnings+errors |
| `dataguard --host 127.0.0.1` | Bind to localhost only |
| `dataguard --version` | Show version |

Test via proxy:
```bash
curl -x http://127.0.0.1:8080 http://httpbin.org/get
```

## Dashboard

Web UI at `http://localhost:8080/`:
- Live stats cards (requests, PII blocked, req/s)
- Scrub playground (test sample text)
- PII presets browser (search/filter)
- Live audit feed (SSE-powered, no refresh)

## Troubleshooting

### Connection refused
```bash
ss -tlnp | grep 8080        # Linux
netstat -ano | findstr 8080 # Windows
dataguard --port 8080 --log-level debug
```

### Empty reply (cannot reach upstream)
- Check network connectivity to LLM provider
- Increase `upstream.timeout` in config
- Check firewall rules

### PII not scrubbed
1. Verify `scrubber.enabled: true`
2. Check content-type is text (not binary/octet-stream)
3. Lower `scrubber.min_confidence` (try `0.3`)
4. Ensure body is not chunked beyond buffer

### High memory usage
```yaml
proxy:
  buffer_size: 16384
  max_concurrent_connections: 1000
```

### Rate limit too aggressive
```yaml
ratelimiter:
  rate: 50.0
  capacity: 200
  per_minute: 3000
```

### Tenant not found / fallback to default
```bash
ls tenants/    # check YAML files exist
# Must have tenant_id field matching the filename
```

### Windows MSYS2 git-bash
```bash
# Use full Python path
/c/Users/HP/AppData/Local/hermes/hermes-agent/venv/Scripts/python.exe -m src.main --port 8080

# Or set alias in ~/.bashrc
alias dataguard="winpty python -m src.main"
```

## Security

- Runs non-root in Docker
- No external network calls, fully self-hosted
- Audit log is append-only with hash chain integrity
- PII never leaves your infrastructure
- Validated: 0 secrets in code, 0 HIGH vulns (SkillSpector)

### Hardening (production)
1. Always run as non-root (default in Docker)
2. Set `scrubber.fail_closed: true`
3. Restrict `tenants/` directory permissions (chmod 600)
4. Put dashboard behind reverse proxy with auth (nginx/traefik)
5. Rotate `DG_ENCRYPTION_KEY` periodically
6. Enable Redis for multi-instance rate limiting

## GDPR / Compliance

| Requirement | Support |
|-------------|---------|
| Data minimization | PII redacted before leaving network |
| Right to erasure | Delete tenant config + audit log anytime |
| Audit trail | Append-only JSONL with hash chain |
| Storage limitation | Configurable log rotation + compression |
| Data portability | Tenant configs are plain YAML |
| Lawful basis | Self-hosted, you are the processor |
| Cross-border | 100% on your infra, no data leaves |
| Confidentiality | AES-GCM encryption at rest (opt-in) |

## Verification Checklist

After any install or config change, verify:
- `dataguard --version` works
- `dataguard --generate-config config.yaml` creates file
- `dataguard --port 18080 --log-level debug` starts cleanly
- `curl -x http://127.0.0.1:18080 http://httpbin.org/get` returns upstream response
- Dashboard at `http://127.0.0.1:18080/` shows live stats
- Scrub playground detects `test@example.com`
- `docker-compose build` succeeds
- `pytest tests/` passes (if dev install)

## Pitfalls

- **DON'T** forget to activate venv before running
- **DON'T** set `min_confidence: 0.0` in production (false positives)
- **DON'T** expose port 8080 publicly without auth reverse proxy
- **DON'T** store real config.yaml with secrets in git
- **DON'T** forget to rotate `DG_ENCRYPTION_KEY`
- **DO** run as non-root, use `fail_closed`, restrict `tenants/` perms
- **DO** use Redis for multi-instance deployments
- **DO** monitor audit log disk usage

## References

- Full architecture: `docs/ARCHITECTURE.md` (2229 lines)
- Security policy: `SECURITY.md`
- Changelog: `CHANGELOG.md`
- PII presets source: `src/scrubber.py`
- Config schema: `src/config.py`
