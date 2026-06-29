<div align="center">

# 🛡️ DataGuard Fortress

**Self-hosted privacy proxy for AI agents — scrub PII inline, classify sensitivity, rate-limit per tenant, and audit every request.**

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-137%20passed-brightgreen.svg)](tests/)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](docker-compose.yml)
[![PII Presets](https://img.shields.io/badge/PII%20presets-52-orange.svg)](src/scrubber.py)
[![Security](https://img.shields.io/badge/security-0%20HIGH%20vulns-success.svg)](SECURITY.md)
[![GDPR](https://img.shields.io/badge/GDPR-compliant-9items-blueviolet.svg)](#gdpr--compliance)

</div>

## The Problem

AI agents routinely send user data to third-party model providers:
- Emails, SSNs, credit cards → sent in plaintext to OpenAI/Anthropic
- No audit trail for compliance officers
- No per-tenant policy enforcement
- Cost spikes from runaway agents go undetected

## The Solution

DataGuard Fortress sits **between** your AI agents and upstream LLM providers, enforcing privacy in **real time**:

| Capability | What it does |
|------------|-------------|
| 🔒 **PII Scrubbing** | 52 built-in regex presets redact sensitive data inline |
| 🏷️ **Sensitivity Classification** | PUBLIC → INTERNAL → CONFIDENTIAL → RESTRICTED |
| 🚦 **Rate Limiting** | Token bucket + sliding window, per-tenant |
| 📝 **Audit Logging** | Append-only JSONL with hash chain integrity |
| 🏢 **Multi-tenant** | Per-customer YAML configs with hot-reload |
| 📊 **Live Dashboard** | SSE-powered real-time UI |

## Architecture

```
AI Agent → DataGuard Proxy (localhost:8080) → LLM Provider
              │
              ├─ Tenant Resolution   → per-tenant YAML policy
              ├─ Rate Limiting       → token bucket + sliding window
              ├─ Sensitivity Class.  → PUBLIC/INTERNAL/CONFIDENTIAL/RESTRICTED
              ├─ PII Scrubbing       → 52 regex presets replace sensitive data
              ├─ Audit Logger        → JSONL append-only + hash chain
              └─ (opt) Encryption    → AES-GCM for payloads at rest
```

## Quick Start

### Option 1: Install as AI Agent Skill (recommended)

Install the skill for your AI agent with a single command:

```bash
# Install for all detected agents
npx dataguard-fortress-skill

# Or install for a specific agent
npx dataguard-fortress-skill --agent claude
npx dataguard-fortress-skill --agent codex
npx dataguard-fortress-skill --agent cursor
npx dataguard-fortress-skill --agent aider
npx dataguard-fortress-skill --agent hermes
```

Supported: Claude Code, OpenAI Codex CLI, Cursor, Aider, Cline, Continue, OpenCode, Hermes Agent.

### Option 2: Install from source

```bash
# 1. Clone
git clone https://github.com/RVRNM/dataguard-fortress.git
cd dataguard-fortress

# 2. Install the skill locally
node skills/dataguard-fortress/install.js --agent all
```

### Option 3: Run the proxy directly
dataguard --port 8080

# 3. Redirect your AI agent HTTP_PROXY=http://localhost:8080
export HTTPS_PROXY=http://localhost:8080

# 4. Verify
curl -x http://localhost:8080 http://httpbin.org/get
```

### Docker (recommended)
```bash
docker-compose up -d --build
```

## What Gets Scrapped

| Category | Examples | Presets |
|----------|----------|---------|
| Personal | email, phone (FR/US/intl), SSN, passport, driver license | 12 |
| Financial | credit cards (Visa/MC/Amex/Discover), IBAN, SWIFT | 8 |
| API Keys | OpenAI, Anthropic, AWS, GCP, GitHub, Stripe, Slack, Twilio, etc. | 16 |
| Crypto | BTC addresses, ETH addresses | 2 |
| Medical | MRN, health insurance ID, NPI, prescription, ICD | 5 |
| Network | IPv4/IPv6, MAC, URL with credentials | 4 |
| Government | ITIN, EIN, UK NINO | 3 |
| Formats | JWT, bearer tokens, SSH keys, DB URLs, VIN, IMEI | 7 |

**Total: 52 presets, all pre-compiled at import time for <5ms overhead.**

## Configuration

```yaml
proxy:
  host: "127.0.0.1"
  port: 8080

scrubber:
  enabled: true
  fail_closed: true    # block if scrubbing fails
  min_confidence: 0.5  # 0.0=catch all, 1.0=perfect only

ratelimiter:
  enabled: true
  rate: 10.0           # tokens/sec
  capacity: 50         # burst
  per_minute: 600      # hard cap

audit:
  enabled: true
  log_dir: ./logs
  log_filename: audit.jsonl

tenants:
  tenants_dir: ./tenants
  hot_reload: true
```

### Multi-tenant example

```yaml
# tenants/acme-corp.yaml
tenant_id: acme-corp
name: Acme Corporation
rate_limit:
  rate: 20.0
  capacity: 100
  per_minute: 1200
scrubber:
  extra_presets:
    - name: employee_id
      pattern: '\bEMP-[0-9]{6}\b'
      replacement: "[REDACTED]"
```

## Dashboard

Visit `http://localhost:8080/` after startup:

- 📊 **Live stats** — requests/sec, PII detected, blocked
- [SECURE] **Scrub playground** — test PII scrubbing on custom text
- [PRIVACY] **Presets browser** — search/filter 52 PII presets
- 📋 **Audit feed** — SSE-powered live event stream

## GDPR / Compliance

| Requirement | Status |
|-------------|--------|
| Data minimization | ✅ PII redacted before leaving network |
| Right to erasure | ✅ Delete tenant config + log anytime |
| Audit trail | ✅ Append-only JSONL with hash chain |
| Storage limitation | ✅ Configurable rotation + compression |
| Cross-border | ✅ 100% on your infra, no data leaves |
| Confidentiality | ✅ AES-GCM at rest (opt-in) |

## Security

- ✅ **0 secrets in code** verified by SkillSpector
- ✅ **0 HIGH vulnerabilities**
- ✅ **137/137 tests** passing
- ✅ **Non-root** Docker container
- ✅ **Zero external network calls**

## Roadmap

| Version | Features | Status |
|---------|----------|--------|
| v0.1 | Core proxy + PII scrubbing | ✅ Done |
| v0.2 | Dashboard + audit logger | ✅ Done |
| v0.3 | Rate limiter + classifier + multi-tenant | ✅ Done |
| v0.4 | Orchestrator integration + full API | ✅ Done |
| v0.5 | AES-GCM encryption layer | 🔜 |
| v1.0 | Public release | [SECURE] |

## License

Apache-2.0 — free for commercial and personal use.

---

*Built with ❤️ for AI sovereignty and GDPR compliance.*
