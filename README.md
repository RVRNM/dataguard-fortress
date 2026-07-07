<div align="center">

# 🛡️ DataGuard Fortress

**Self-hosted privacy proxy for AI agents — scrub PII inline, classify sensitivity, rate-limit per tenant, and audit every request.**

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue?logo=python&logoColor=white)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-Apache%202.0-green?logo=apache)](LICENSE)
[![CI](https://github.com/RVRNM/dataguard-fortress/actions/workflows/ci.yml/badge.svg)](https://github.com/RVRNM/dataguard-fortress/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/tests-99%20passing-brightgreen?logo=pytest)](tests/)
[![Coverage](https://img.shields.io/badge/coverage-67%25-yellow?logo=codecov)](pyproject.toml)
[![Docker](https://img.shields.io/badge/docker-ready-2496ED?logo=docker&logoColor=white)](docker-compose.yml)
[![Release](https://img.shields.io/github/v/release/RVRNM/dataguard-fortress?logo=github)](https://github.com/RVRNM/dataguard-fortress/releases)
[![GDPR](https://img.shields.io/badge/GDPR-compliant-6a0dad?logo=gdpr)](#gdpr--compliance)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen?logo=github)](/../../pulls)

</div>

---

## 📋 Table of Contents

- [The Problem](#the-problem)
- [Quick Start (5 min)](#quick-start)
- [Features](#features)
- [What Gets Scrubbed](#what-gets-scrubbed)
- [Multi-Tenant](#multi-tenant)
- [Dashboard](#dashboard)
- [Configuration](#configuration)
- [Architecture](#architecture)
- [GDPR / Compliance](#gdpr--compliance)
- [Security](#security)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

---

## The Problem

AI agents routinely send user data to third-party model providers without protection:

- 📧 Emails, SSNs, credit cards → sent in plaintext to OpenAI / Anthropic
- 📋 No audit trail for compliance officers
- 👥 No per-tenant policy enforcement
- 💰 Cost spikes from runaway agents go undetected

**Result:** Your company becomes liable for GDPR/CCPA violations.

---

## Quick Start

Get DataGuard running in **5 minutes**:

### Option 1: Docker (Recommended)
```bash
git clone https://github.com/RVRNM/dataguard-fortress.git
cd dataguard-fortress
docker-compose up -d
# Dashboard: http://localhost:8080
```

### Option 2: Local Python
```bash
pip install dataguard-fortress
dataguard --port 8080
```

### Option 3: AI Agent Skill
```bash
node skills/dataguard-fortress/install.js --agent claude
```

✅ **Done!** Your proxy is running. Visit `http://localhost:8080` for the dashboard.

📖 **[Full Quick Start Guide →](docs/QUICKSTART.md)**

---

## Features

| Capability | What it does |
|---|---|
| 🔒 **PII Scrubbing** | 52 built-in regex presets — email, SSN, credit cards, API keys, crypto addresses, medical IDs, and more |
| 🏷️ **Sensitivity Classification** | PUBLIC → INTERNAL → CONFIDENTIAL → RESTRICTED |
| 🚦 **Rate Limiting** | Token bucket + sliding window, per-tenant configurable |
| 📝 **Audit Logging** | Append-only JSONL with SHA-256 hash chain integrity |
| 🏢 **Multi-Tenant** | Per-customer YAML configs with hot-reload at runtime |
| 🔐 **Payload Encryption** | AES-GCM 256-bit encryption for data at rest |
| 📊 **Live Dashboard** | SSE-powered real-time metrics and audit feed |

---

## What Gets Scrubbed

**52 PII patterns across 8 categories:**

| Category | Examples | Count |
|---|---|---|
| **Personal** | email, phone (FR/US/intl), SSN, passport, driver license | 12 |
| **Financial** | credit cards (Visa/MC/Amex/Discover), IBAN, SWIFT | 8 |
| **API Keys** | OpenAI, Anthropic, AWS, GCP, GitHub, Stripe, Slack, Twilio | 16 |
| **Crypto** | BTC addresses, ETH addresses | 2 |
| **Medical** | MRN, health insurance ID, NPI, prescription, ICD codes | 5 |
| **Network** | IPv4/IPv6, MAC address, URL with credentials | 4 |
| **Government** | ITIN, EIN, UK NINO | 3 |
| **Formats** | JWT, bearer tokens, SSH keys, DB URLs, VIN, IMEI | 7 |

---

## Multi-Tenant

Each tenant gets isolated configuration, rate limits, and custom PII patterns:

```yaml
# tenants/acme-corp.yaml
tenant_id: acme-corp
rate_limit:
  rate: 20.0           # 20 req/sec
  capacity: 100
  per_minute: 1200
scrubber:
  extra_presets:
    - name: employee_id
      pattern: '\bEMP-[0-9]{6}\b'
      replacement: "[REDACTED]"
```

Configs hot-reload on file change — **no restart required**.

---

## Dashboard

Visit `http://localhost:8080` after startup:

| Feature | Description |
|---|---|
| 📊 **Live stats** | Requests/sec, PII detected, blocked requests |
| 🧪 **Scrub playground** | Test PII scrubbing on custom text in real time |
| 🔍 **Presets browser** | Search and filter all 52 PII presets |
| 📋 **Audit feed** | SSE-powered live event stream |

---

## Configuration

### Minimal Setup

```yaml
proxy:
  host: "0.0.0.0"
  port: 8080

scrubber:
  enabled: true
  fail_closed: true
  min_confidence: 0.85

ratelimiter:
  enabled: true
  rate: 10.0
  per_minute: 600

audit:
  enabled: true
  log_dir: ./logs
```

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `DG_ENCRYPTION_KEY` | — | 256-bit AES-GCM encryption key |
| `DG_REDIS_URL` | — | Redis URL (optional, uses in-memory otherwise) |
| `DG_LOG_LEVEL` | `INFO` | Logging verbosity |
| `DG_CONFIG_PATH` | `./config.yaml` | Custom config location |

---

## Architecture

```
AI Agent ──► DataGuard Proxy (localhost:8080) ──► LLM Provider
                     │
                     ├─ Tenant Resolution   → per-tenant YAML policy
                     ├─ Rate Limiting       → token bucket + sliding window
                     ├─ Sensitivity Class.  → PUBLIC / INTERNAL / CONFIDENTIAL / RESTRICTED
                     ├─ PII Scrubbing       → 52 regex presets
                     ├─ Audit Logger        → JSONL append-only + hash chain
                     └─ (opt) Encryption    → AES-GCM for payloads at rest
```

**Design principles:**
- **Zero egress** — all processing stays on your infrastructure
- **Pluggable backends** — Redis or in-memory for rate limiting
- **Fail-closed by default** — on error, requests are blocked, not leaked
- **No telemetry** — no external network calls from the proxy itself

📖 **[Full Architecture Docs →](docs/ARCHITECTURE.md)**

---

## GDPR / Compliance

| Requirement | Implementation |
|---|---|
| **Data minimization** | PII redacted before leaving your network |
| **Right to erasure** | Delete tenant config + audit logs on demand |
| **Audit trail** | Append-only JSONL with SHA-256 hash chain |
| **Storage limitation** | Configurable log rotation and compression |
| **Cross-border** | 100% on your infrastructure, no data leaves |
| **Confidentiality** | AES-GCM encryption at rest (opt-in) |

---

## Security

- ✅ **0 secrets in source code** — verified by automated scanning
- ✅ **99 tests passing** — lint, type check, security scan, and integration tests
- ✅ **Non-root Docker container** — runs as unprivileged user
- ✅ **Zero external network calls** — no telemetry, no phoning home
- ✅ **Fail-closed architecture** — on error, requests are blocked, not leaked
- ✅ **Dependency scanning** — `pip-audit` runs on every commit

> **Responsible disclosure:** Report vulnerabilities to `security@dataguard-fortress.dev`.  
> We acknowledge reports within 48 hours.

---

## CI/CD Pipeline

| Stage | Status | Description |
|---|---|---|
| **Lint** | ✅ | `ruff check`, `ruff format`, `mypy` — enforces code quality |
| **Test** | ✅ | `pytest` across Python 3.11 · 3.12 · 3.13 with coverage reporting |
| **Security** | ✅ | `pip-audit` (dependency vulnerabilities) + `bandit` (static analysis) |
| **Build** | ✅ | `python -m build` — verifies wheel packaging integrity |

All stages run on every push and pull request to `main`.

---

## Examples & Integrations

### OpenAI
```python
import openai
openai.api_base = "http://localhost:8080"
# PII is automatically scrubbed before reaching OpenAI
```

### Anthropic Claude
```python
import anthropic
client = anthropic.Anthropic(base_url="http://localhost:8080")
# Your data is protected by DataGuard
```

### LangChain
```python
import os
os.environ["OPENAI_API_BASE"] = "http://localhost:8080"
# LangChain requests flow through DataGuard proxy
```

📖 **[Full Integration Examples →](docs/EXAMPLES.md)**

---

## Roadmap

| Version | Features | Status |
|---|---|---|
| v0.1 | Core proxy + PII scrubbing | ✅ Released |
| v0.2 | Dashboard + audit logger | ✅ Released |
| v0.3 | Rate limiter + classifier + multi-tenant | ✅ Released |
| v0.4 | Orchestrator integration + full API | ✅ Released |
| v0.5 | AES-GCM encryption layer | ✅ Released |
| v1.0 | Production hardening, performance benchmarks | 🔜 Next |

---

## Documentation

| Document | Purpose |
|---|---|
| [Quick Start](docs/QUICKSTART.md) | Get running in 5 minutes |
| [Architecture](docs/ARCHITECTURE.md) | Deep dive into how it works |
| [Examples](docs/EXAMPLES.md) | Integration examples (OpenAI, Claude, LangChain, etc.) |
| [CONTRIBUTING](CONTRIBUTING.md) | How to contribute |
| [SECURITY](SECURITY.md) | Security policy & reporting |
| [CHANGELOG](CHANGELOG.md) | Release notes |

---

## Contributing

Contributions are welcome! Please:

1. **Fork** the repository
2. **Create a feature branch** (`git checkout -b feat/my-feature`)
3. **Commit** your changes (`git commit -m 'feat: add my feature'`)
4. **Push** to the branch (`git push origin feat/my-feature`)
5. **Open a Pull Request**

All contributions must follow [Conventional Commits](https://www.conventionalcommits.org/).

---

## Support

- 📖 **Docs:** [docs/](docs/)
- 💬 **Discussions:** [GitHub Discussions](../../discussions)
- 🐛 **Issues:** [GitHub Issues](../../issues)
- 🔐 **Security:** security@dataguard-fortress.dev

---

## License

```
Apache License, Version 2.0 — January 2004

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

---

<div align="center">

**Built with ❤️ for AI sovereignty and data privacy.**

[⭐ Star us on GitHub](https://github.com/RVRNM/dataguard-fortress) · [🐛 Report a bug](../../issues) · [💡 Request a feature](../../issues) · [📖 Full Docs](docs/) · [🔐 Security](SECURITY.md) · [📝 Changelog](CHANGELOG.md)

</div>
