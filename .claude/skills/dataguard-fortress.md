---
name: dataguard-fortress
description: "Operate DataGuard Fortress — self-hosted privacy proxy for AI agents. Use when installing, configuring, running, or troubleshooting DataGuard Fortress."
---

# DataGuard Fortress

Self-hosted privacy proxy for AI agents. Scrubs PII inline, classifies sensitivity, rate-limits per tenant, and audits every request.

## When to Use

- User says "dataguard", "privacy proxy", "PII scrub", "LLM privacy", "AI data protection"
- User wants to intercept and sanitize API calls before they reach LLM providers
- User needs GDPR-compliant LLM usage or audit logging for AI compliance
- User asks about per-tenant proxy policies or rate limiting for AI agents
- User reports a DataGuard Fortress configuration or runtime issue

## Install

```bash
git clone https://github.com/RVRNM/dataguard-fortress.git
cd dataguard-fortress
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[prod]"
```

Verify: `dataguard --version`

## Quick Start

```bash
dataguard --generate-config config.yaml
dataguard --port 8080 &
export HTTP_PROXY=http://localhost:8080
export HTTPS_PROXY=http://localhost:8080
curl -x http://localhost:8080 http://httpbin.org/get
```

## Commands

| Command | Description |
|---------|-------------|
| `dataguard --port 8080` | Start proxy |
| `dataguard --generate-config config.yaml` | Generate default config |
| `dataguard --log-level debug` | Verbose logging |
| `dataguard --version` | Show version |

## Architecture

```
AI Agent → DataGuard Proxy (:8080) → LLM Provider
              ├─ Tenant Resolution   → per-tenant YAML policy
              ├─ Rate Limiting       → token bucket + sliding window
              ├─ Sensitivity Class.  → PUBLIC/INTERNAL/CONFIDENTIAL/RESTRICTED
              ├─ PII Scrubbing       → 52 regex presets
              ├─ Audit Logger        → JSONL append-only + hash chain
              └─ (opt) Encryption    → AES-GCM
```

## Troubleshooting

- **Connection refused**: `dataguard --port 8080 --log-level debug`
- **PII not scrubbed**: check `scrubber.enabled: true`, lower `min_confidence`
- **High memory**: reduce `proxy.buffer_size` to 16384
- **Rate limit too aggressive**: increase `rate_limit.rate` to 50.0

## Config Reference

```yaml
proxy:
  host: "127.0.0.1"
  port: 8080
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
tenants:
  tenants_dir: ./tenants
  hot_reload: true
```
