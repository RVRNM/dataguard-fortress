# DataGuard Fortress — Architecture Document

> **Version:** 0.1.0-draft  
> **Status:** Pre-release  
> **Date:** 2026-06-29  
> **License:** Apache-2.0  

---

## Table of Contents

1. [README / Project Overview](#1-readme--project-overview)
2. [High-Level Architecture](#2-high-level-architecture)
3. [Network Architecture](#3-network-architecture)
4. [Component Breakdown](#4-component-breakdown)
5. [API & Dashboard Endpoints](#5-api--dashboard-endpoints)
6. [Configuration Schema](#6-configuration-schema)
7. [Docker & Docker-Compose Setup](#7-docker--docker-compose-setup)
8. [CI/CD Pipeline (GitHub Actions)](#8-cicd-pipeline-github-actions)
9. [Security Model](#9-security-model)
10. [Performance Targets](#10-performance-targets)
11. [Audit Log Data Schema](#11-audit-log-data-schema)
12. [Testing Strategy](#12-testing-strategy)
13. [Roadmap to v1.0](#13-roadmap-to-v10)
14. [Appendix A — Glossary](#appendix-a--glossary)
15. [Appendix B — References](#appendix-b--references)

---

## 1. README / Project Overview

### 1.1 What Is DataGuard Fortress?

**DataGuard Fortress** is an open-source, high-performance privacy proxy for AI
agents. It sits between AI-powered applications (chatbots, copilots, autonomous
agents, RAG pipelines) and upstream LLM/API providers, enforcing privacy
policies in real time:

- **Scrubbing** personally identifiable information (PII) and sensitive data
  from prompts before they leave the trust boundary.
- **Encrypting** payloads end-to-end where required by policy.
- **Classifying** data sensitivity levels to apply the correct handling rules.
- **Rate-limiting** requests to prevent abuse and cost overruns.
- **Auditing** every transaction to an append-only JSONL log for compliance.

### 1.2 Why It Exists

AI agents routinely send user data to third-party model providers. Existing
solutions either:

| Gap | Example |
|-----|---------|
| No inline PII scrubbing | Agents send raw emails, SSNs, API keys to OpenAI/Anthropic |
| No per-tenant policy enforcement | Multi-tenant SaaS platforms lack per-customer privacy rules |
| No audit trail | Compliance officers cannot reconstruct what data went where |
| No unified rate limiting | Cost spikes from runaway agents go undetected |
| No sensitivity classification | All data treated equally regardless of classification level |

DataGuard Fortress closes all five gaps with a single, self-hosted proxy that
is configuration-driven, extensible, and auditable.

### 1.3 Design Principles

1. **Zero-trust by default.** Every inbound request is untrusted until
   classified and scrubbed.
2. **Configuration-driven.** All policies expressed in YAML; no code changes
   needed to tighten or relax rules.
3. **Low-latency.** Proxy adds < 5 ms p99 overhead on the critical path.
4. **Observable.** Every request produces a structured audit event.
5. **Extensible.** Scrubbers, classifiers, and encryptors are pluggable via
   a registry pattern.
6. **Fail-closed.** If classification or scrubbing fails, the request is
   rejected, never leaked.

### 1.4 Technology Stack

| Layer | Technology |
|-------|-----------|
| Runtime | Python 3.12+ |
| Async framework | asyncio + uvloop |
| HTTP proxy | FastAPI + httpx (async) |
| PII detection | Presidio (Microsoft) + regex fallback |
| Encryption | cryptography (Fernet / AES-256-GCM) |
| Rate limiting | redis + custom token-bucket |
| Classification | rule-based + optional ML (spaCy NER) |
| Audit storage | JSONL files + optional Redis Stream / S3 |
| Dashboard | FastAPI served SPA (Vue.js 3) |
| Containerisation | Docker + docker-compose |
| CI/CD | GitHub Actions |
| Testing | pytest + pytest-asyncio + httpx TestClient |

### 1.5 Project Structure

```
dataguard-fortress/
├── src/
│   └── dataguard/
│       ├── __init__.py
│       ├── main.py                  # FastAPI app entry
│       ├── proxy/                   # Proxy core
│       │   ├── __init__.py
│       │   ├── server.py            # Proxy server
│       │   ├── handler.py           # Request handler
│       │   ├── middleware.py        # ASGI middleware chain
│       │   └── routing.py           # Upstream routing
│       ├── scrubber/                # PII scrubbing
│       │   ├── __init__.py
│       │   ├── engine.py            # Scrubber orchestration
│       │   ├── presidio.py          # Presidio integration
│       │   ├── regex.py             # Regex-based scrubbers
│       │   └── custom.py            # User-defined scrubbers
│       ├── encryptor/               # Encryption layer
│       │   ├── __init__.py
│       │   ├── engine.py            # Encryptor orchestration
│       │   ├── fernet.py            # Fernet symmetric
│       │   └── aes_gcm.py           # AES-256-GCM
│       ├── classifier/              # Sensitivity classification
│       │   ├── __init__.py
│       │   ├── engine.py            # Classifier orchestration
│       │   ├── rule_based.py        # Rule-based classifier
│       │   └── ml.py                # ML NER classifier
│       ├── ratelimiter/             # Rate limiting
│       │   ├── __init__.py
│       │   ├── engine.py            # Rate limiter orchestration
│       │   ├── token_bucket.py      # Token bucket algo
│       │   └── redis_store.py       # Redis-backed state
│       ├── audit/                   # Audit logging
│       │   ├── __init__.py
│       │   ├── engine.py            # Audit orchestration
│       │   ├── jsonl_writer.py      # JSONL file writer
│       │   ├── redis_writer.py      # Redis Stream writer
│       │   └── s3_writer.py         # S3 writer
│       ├── dashboard/               # Web dashboard
│       │   ├── __init__.py
│       │   ├── app.py               # Dashboard FastAPI sub-app
│       │   └── static/              # Vue.js SPA
│       ├── config/                  # Configuration
│       │   ├── __init__.py
│       │   ├── loader.py            # YAML loader + validator
│       │   ├── schema.py            # Pydantic config schema
│       │   └── defaults.py          # Default settings
│       ├── models/                  # Shared data models
│       │   ├── __init__.py
│       │   ├── request.py           # Proxy request models
│       │   ├── response.py          # Proxy response models
│       │   └── audit.py             # Audit event models
│       ├── security/                # Security utilities
│       │   ├── __init__.py
│       │   ├── secrets.py           # Secret management
│       │   ├── tls.py               # TLS configuration
│       │   └── headers.py           # Security headers
│       └── utils/                   # Shared utilities
│           ├── __init__.py
│           ├── logging.py           # Structured logging
│           ├── metrics.py           # Prometheus metrics
│           └── retry.py             # Retry logic
├── tests/
│   ├── unit/
│   ├── integration/
│   └── e2e/
├── docs/
│   └── ARCHITECTURE.md              # This document
├── docker/
│   ├── Dockerfile
│   └── Dockerfile.slim
├── docker-compose.yml
├── .github/
│   └── workflows/
│       ├── ci.yml
│       ├── security.yml
│       └── release.yml
├── config/
│   └── default.yaml                 # Default config file
├── pyproject.toml
├── Makefile
└── README.md
```

---

## 2. High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                        AI Agent / Client                            │
│  (Copilot, Chatbot, RAG Pipeline, Autonomous Agent, SDK)            │
└──────────────────────────┬───────────────────────────────────────────┘
                           │  HTTP/HTTPS
                           ▼
┌──────────────────────────────────────────────────────────────────────┐
│                     DataGuard Fortress Proxy                        │
│                                                                      │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌────────────┐ │
│  │  Classifier  │→│  Scrubber   │→│  Encryptor  │→│ Rate Limiter│ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └────────────┘ │
│          │                                       │                  │
│          ▼                                       ▼                  │
│  ┌─────────────┐                         ┌──────────────┐          │
│  │Policy Engine│                         │ Audit Logger │          │
│  └─────────────┘                         └──────────────┘          │
│          │                                       │                  │
│          └───────────────┬───────────────────────┘                  │
│                          │                                           │
│  ┌───────────────────────▼──────────────────────────┐              │
│  │            Upstream Router / Handler              │              │
│  └───────────────────────┬──────────────────────────┘              │
└──────────────────────────┼──────────────────────────────────────────┘
                           │  HTTP/HTTPS
                           ▼
┌──────────────────────────────────────────────────────────────────────┐
│                Upstream LLM Provider (OpenAI, Anthropic, etc.)       │
└──────────────────────────────────────────────────────────────────────┘
```

### 2.1 Request Lifecycle

1. **Inbound** — Client sends request to proxy.
2. **Authentication** — Proxy validates API key / JWT.
3. **Classification** — Request body is classified for sensitivity level.
4. **Scrubbing** — PII is redacted or replaced based on classification.
5. **Encryption** — Sensitive fields are encrypted if policy requires.
6. **Rate Check** — Token-bucket rate limiter admits or rejects.
7. **Audit (pre)** — Pre-flight audit event is logged.
8. **Forward** — Proxied request is sent to upstream LLM provider.
9. **Response Processing** — Response is optionally decrypted / scrubbed.
10. **Audit (post)** — Post-flight audit event is logged.
11. **Return** — Processed response is returned to the client.

### 2.2 Failure Modes

| Failure | Behaviour |
|---------|-----------|
| Classification error | Reject request (fail-closed) |
| Scrubber exception | Reject request (fail-closed) |
| Encryption error | Reject request (fail-closed) |
| Rate limit exceeded | Return HTTP 429 with Retry-After header |
| Upstream timeout | Return HTTP 504, log event |
| Audit write failure | Log warning, continue (non-blocking) |
| Redis unavailable | Fall back to in-memory rate limiting |

---

## 3. Network Architecture

### 3.1 Deployment Topology

```
                    ┌─────────────────────┐
                    │   Load Balancer      │
                    │   (nginx / Caddy)    │
                    │   TLS termination    │
                    └──────────┬──────────┘
                               │
              ┌────────────────┼────────────────┐
              │                │                │
    ┌─────────▼──────┐  ┌─────▼────────┐  ┌────▼─────────┐
    │  DG-Fortress   │  │  DG-Fortress │  │  DG-Fortress │
    │  Instance 1    │  │  Instance 2  │  │  Instance N  │
    │  (port 8000)   │  │  (port 8000) │  │  (port 8000) │
    └────┬───────────┘  └─────┬────────┘  └────┬─────────┘
         │                     │                 │
         └─────────────┬──────┘────────────────┘
                        │
         ┌──────────────┼──────────────┐
         │              │              │
    ┌────▼─────┐  ┌─────▼─────┐  ┌────▼────┐
    │  Redis   │  │  Audit    │  │ S3/MinIO│
    │  (6379)  │  │  JSONL    │  │ (logs)  │
    └──────────┘  └───────────┘  └─────────┘
```

### 3.2 Network Zones

| Zone | CIDR | Purpose | Trust Level |
|------|------|---------|-------------|
| Public | 0.0.0.0/0 | Load balancer ingress | Untrusted |
| DMZ | 10.0.1.0/24 | LB → Proxy instances | Semi-trusted |
| App | 10.0.2.0/24 | Proxy → Redis / Audit / S3 | Trusted |
| Egress | 10.0.3.0/24 | Proxy → Upstream LLM APIs | Semi-trusted |
| Management | 10.0.99.0/24 | Dashboard / metrics / SSH | Restricted |

### 3.3 TLS Configuration

All external communication MUST use TLS 1.3. Internal communication within
the trusted app zone MAY use plaintext for performance, but MUST be configured
via `config.tls.internal.enabled`.

```yaml
tls:
  external:
    enabled: true
    cert_file: /etc/dataguard/tls/server.crt
    key_file: /etc/dataguard/tls/server.key
    min_version: "1.3"
    cipher_suites:
      - TLS_AES_256_GCM_SHA384
      - TLS_CHACHA20_POLY1305_SHA256
  internal:
    enabled: false  # plaintext within trusted zone
```

### 3.4 Port Allocation

| Port | Protocol | Service | Exposed |
|------|----------|---------|---------|
| 8000 | HTTP | Proxy API | Via LB |
| 8001 | HTTP | Dashboard | Internal |
| 9090 | HTTP | Prometheus metrics | Internal |
| 6379 | TCP | Redis | Internal only |

### 3.5 DNS & Service Discovery

- Internal services use Docker DNS (service names).
- Production uses Consul or Kubernetes Service discovery.
- Upstream LLM providers resolved via public DNS with DNS-over-HTTPS.

### 3.6 Firewall Rules

```bash
# Egress: only HTTPS to LLM providers
iptables -A OUTPUT -p tcp --dport 443 -d api.openai.com -j ACCEPT
iptables -A OUTPUT -p tcp --dport 443 -d api.anthropic.com -j ACCEPT
iptables -A OUTPUT -p tcp --dport 443 -j DROP  # deny all other egress

# Ingress: only from load balancer
iptables -A INPUT -p tcp --dport 8000 -s 10.0.1.0/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 8000 -j DROP
```

---

## 4. Component Breakdown

### 4.1 Proxy Core

The proxy core is the entrypoint and orchestrator for all requests. It is
implemented as a FastAPI application with custom ASGI middleware.

#### 4.1.1 Server (`src/dataguard/proxy/server.py`)

```python
"""Proxy server — FastAPI application factory."""

from fastapi import FastAPI
from dataguard.proxy.middleware import (
    AuthMiddleware,
    ClassificationMiddleware,
    ScrubberMiddleware,
    EncryptorMiddleware,
    RateLimiterMiddleware,
    AuditMiddleware,
)
from dataguard.proxy.handler import ProxyHandler
from dataguard.config.loader import load_config
from dataguard.utils.logging import setup_logging
from dataguard.utils.metrics import setup_metrics


def create_app(config_path: str = "config/default.yaml") -> FastAPI:
    """Create and configure the proxy FastAPI application."""
    config = load_config(config_path)
    setup_logging(config.logging)
    
    app = FastAPI(
        title="DataGuard Fortress",
        version="0.1.0",
        docs_url=None,       # Disable Swagger UI in production
        redoc_url=None,      # Disable ReDoc in production
    )
    
    # Middleware stack (executed in reverse order — last added runs first)
    app.add_middleware(AuditMiddleware, config=config.audit)
    app.add_middleware(RateLimiterMiddleware, config=config.ratelimiter)
    app.add_middleware(EncryptorMiddleware, config=config.encryptor)
    app.add_middleware(ScrubberMiddleware, config=config.scrubber)
    app.add_middleware(ClassificationMiddleware, config=config.classifier)
    app.add_middleware(AuthMiddleware, config=config.auth)
    
    # Register proxy route
    handler = ProxyHandler(config)
    app.add_api_route(
        "/v1/{path:path}",
        handler.proxy_request,
        methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    )
    
    setup_metrics(app, config.metrics)
    return app
```

#### 4.1.2 Handler (`src/dataguard/proxy/handler.py`)

The handler receives the already-processed (classified, scrubbed, encrypted,
rate-checked) request and forwards it to the upstream LLM provider.

```python
"""Proxy request handler — forwards to upstream LLM providers."""

import httpx
from fastapi import Request, Response
from dataguard.proxy.routing import UpstreamRouter
from dataguard.audit.engine import AuditEngine
from dataguard.models.request import ProxyRequest
from dataguard.models.response import ProxyResponse


class ProxyHandler:
    def __init__(self, config):
        self.router = UpstreamRouter(config.upstreams)
        self.client = httpx.AsyncClient(
            timeout=httpx.Timeout(
                connect=5.0,
                read=config.upstreams.timeout,
                write=5.0,
                pool=5.0,
            ),
            limits=httpx.Limits(
                max_connections=config.upstreams.max_connections,
                max_keepalive_connections=config.upstreams.max_keepalive,
            ),
        )
        self.audit = AuditEngine(config.audit)
    
    async def proxy_request(self, request: Request, path: str) -> Response:
        """Forward the processed request to the appropriate upstream."""
        # Build upstream URL
        upstream = self.router.resolve(path, request.headers)
        
        # Stream or buffer the request body
        body = await request.body()
        
        # Forward headers (filter hop-by-hop)
        fwd_headers = self.router.filter_headers(request.headers)
        
        # Send to upstream
        upstream_resp = await self.client.request(
            method=request.method,
            url=upstream.url,
            content=body,
            headers=fwd_headers,
        )
        
        # Build downstream response
        return Response(
            content=upstream_resp.content,
            status_code=upstream_resp.status_code,
            headers=dict(upstream_resp.headers),
        )
```

#### 4.1.3 Middleware Chain

Each middleware follows the same contract:

```python
from starlette.middleware.base import BaseHTTPMiddleware

class ExampleMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Pre-processing
        modified_request = await self.process_request(request)
        # Call next middleware / handler
        response = await call_next(modified_request)
        # Post-processing
        modified_response = await self.process_response(response)
        return modified_response
```

Middleware execution order (first = outermost):

1. `AuthMiddleware` — validates API key / JWT
2. `ClassificationMiddleware` — classifies request sensitivity
3. `ScrubberMiddleware` — scrubs PII from request body
4. `EncryptorMiddleware` — encrypts sensitive fields
5. `RateLimiterMiddleware` — checks rate limits
6. `AuditMiddleware` — logs audit events

#### 4.1.4 Upstream Router (`src/dataguard/proxy/routing.py`)

Routes requests to the correct upstream LLM provider based on:

- **Path prefix** — `/v1/openai/...` → OpenAI, `/v1/anthropic/...` → Anthropic
- **Header** — `X-DG-Upstream: openai`
- **Model name** — extracted from request body JSON `model` field
- **Default** — configured default upstream

```python
class UpstreamRouter:
    def __init__(self, config: UpstreamsConfig):
        self.routes = {}
        for upstream in config.providers:
            self.routes[upstream.name] = upstream
    
    def resolve(self, path: str, headers: Headers) -> UpstreamConfig:
        """Resolve the target upstream for this request."""
        # 1. Check explicit header
        if "x-dg-upstream" in headers:
            return self.routes[headers["x-dg-upstream"]]
        # 2. Check path prefix
        prefix = path.split("/")[0]
        if prefix in self.routes:
            return self.routes[prefix]
        # 3. Default
        return self.routes[self.config.default]
```

---

### 4.2 Scrubber

The scrubber removes or replaces PII from request bodies before they are
sent upstream.

#### 4.2.1 Engine (`src/dataguard/scrubber/engine.py`)

```python
"""Scrubber engine — orchestrates PII detection and redaction."""

from dataclasses import dataclass
from typing import Any

@dataclass
class ScrubResult:
    """Result of a scrubbing operation."""
    original_text: str
    scrubbed_text: str
    detections: list[dict]     # list of (type, start, end, confidence)
    scrubbed_count: int
    policy_applied: str


class ScrubberEngine:
    """Main scrubber that runs all registered scrubbers."""
    
    def __init__(self, config: ScrubberConfig):
        self.scrubbers = []
        if config.presidio.enabled:
            from dataguard.scrubber.presidio import PresidioScrubber
            self.scrubbers.append(PresidioScrubber(config.presidio))
        if config.regex.enabled:
            from dataguard.scrubber.regex import RegexScrubber
            self.scrubbers.append(RegexScrubber(config.regex))
        for custom in config.custom:
            self.scrubbers.append(load_custom_scrubber(custom))
    
    async def scrub(self, text: str, sensitivity: str) -> ScrubResult:
        """Run all scrubbers against the text."""
        result = ScrubResult(
            original_text=text,
            scrubbed_text=text,
            detections=[],
            scrubbed_count=0,
            policy_applied=sensitivity,
        )
        for scrubber in self.scrubbers:
            partial = await scrubber.detect_and_redact(result.scrubbed_text)
            result.scrubbed_text = partial.text
            result.detections.extend(partial.detections)
            result.scrubbed_count += partial.count
        return result
    
    async def scrub_json(self, data: dict, sensitivity: str) -> dict:
        """Scrub all string values in a JSON structure."""
        return await self._walk_json(data, sensitivity)
```

#### 4.2.2 Presidio Integration (`src/dataguard/scrubber/presidio.py`)

Uses Microsoft Presidio for NLP-based PII detection:

- **Analyzers**: `CreditCardAnalyzer`, `EmailAnalyzer`, `PhoneNumberAnalyzer`,
  `SsnAnalyzer`, `UsPassportAnalyzer`, `IpAddressAnalyzer`, etc.
- **Anonymizers**: Replace with `[REDACTED_<TYPE>]`, hash, or mask patterns.
- **Language support**: English (default), extendable to 20+ languages.

```python
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine

class PresidioScrubber:
    def __init__(self, config):
        self.analyzer = AnalyzerEngine()
        self.anonymizer = AnonymizerEngine()
        self.threshold = config.confidence_threshold  # default 0.5
        self.allowed_entities = config.entities  # e.g. ["EMAIL_ADDRESS", "PHONE_NUMBER"]
    
    async def detect_and_redact(self, text: str) -> ScrubPartial:
        results = self.analyzer.analyze(
            text=text,
            entities=self.allowed_entities,
            language="en",
            score_threshold=self.threshold,
        )
        anonymized = self.anonymizer.anonymize(text=text, analyzer_results=results)
        return ScrubPartial(
            text=anonymized.text,
            detections=[r.__dict__ for r in results],
            count=len(results),
        )
```

#### 4.2.3 Regex Scrubber (`src/dataguard/scrubber/regex.py`)

Fast regex-based detection for high-throughput paths:

| Entity | Pattern | Replacement |
|--------|---------|-------------|
| SSN | `\d{3}-\d{2}-\d{4}` | `[REDACTED_SSN]` |
| Credit Card | `\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}` | `[REDACTED_CC]` |
| Email | `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}` | `[REDACTED_EMAIL]` |
| Phone | `\+?1?\s*\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}` | `[REDACTED_PHONE]` |
| API Key | `(sk-|pk-|key-)[a-zA-Z0-9]{20,}` | `[REDACTED_API_KEY]` |
| AWS Key | `AKIA[0-9A-Z]{16}` | `[REDACTED_AWS_KEY]` |
| IP Address | `\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}` | `[REDACTED_IP]` |

#### 4.2.4 Custom Scrubbers (`src/dataguard/scrubber/custom.py`)

Users can register custom scrubbers via entry points:

```python
# In pyproject.toml:
[project.entry-points."dataguard.scrubbers"]
medical_record = "my_package.scrubbers:MedicalRecordScrubber"

# The scrubber must implement:
class BaseScrubber(Protocol):
    async def detect_and_redact(self, text: str) -> ScrubPartial: ...
```

---

### 4.3 Encryptor

The encryptor applies field-level encryption to sensitive data that must be
preserved (not scrubbed) but protected in transit or at rest.

#### 4.3.1 Engine (`src/dataguard/encryptor/engine.py`)

```python
"""Encryptor engine — orchestrates field-level encryption."""

class EncryptorEngine:
    def __init__(self, config: EncryptorConfig):
        self.provider = self._load_provider(config)
        self.field_selector = FieldSelector(config.fields)
    
    async def encrypt_request(self, body: dict, classification: str) -> dict:
        """Encrypt specified fields in request body."""
        fields_to_encrypt = self.field_selector.select(body, classification)
        for path in fields_to_encrypt:
            value = jsonpath_get(body, path)
            encrypted = await self.provider.encrypt(str(value))
            jsonpath_set(body, path, f"ENC({encrypted})")
        return body
    
    async def decrypt_response(self, body: dict) -> dict:
        """Decrypt fields in response body."""
        encrypted_fields = self._find_encrypted_fields(body)
        for path in encrypted_fields:
            value = jsonpath_get(body, path)
            decrypted = await self.provider.decrypt(value)
            jsonpath_set(body, path, decrypted)
        return body
```

#### 4.3.2 Fernet Provider (`src/dataguard/encryptor/fernet.py`)

Symmetric encryption using Fernet (AES-128-CBC + HMAC-SHA256):

```python
from cryptography.fernet import Fernet

class FernetProvider:
    def __init__(self, key: bytes):
        self.fernet = Fernet(key)
    
    async def encrypt(self, plaintext: str) -> str:
        return self.fernet.encrypt(plaintext.encode()).decode()
    
    async def decrypt(self, ciphertext: str) -> str:
        return self.fernet.decrypt(ciphertext.encode()).decode()
```

#### 4.3.3 AES-256-GCM Provider (`src/dataguard/encryptor/aes_gcm.py`)

Authenticated encryption with associated data (AEAD):

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class AESGCMProvider:
    def __init__(self, key: bytes):
        self.aesgcm = AESGCM(key)  # 256-bit key
    
    async def encrypt(self, plaintext: str, aad: bytes = b"") -> str:
        nonce = os.urandom(12)
        ct = self.aesgcm.encrypt(nonce, plaintext.encode(), aad)
        return base64.urlsafe_b64encode(nonce + ct).decode()
    
    async def decrypt(self, ciphertext: str, aad: bytes = b"") -> str:
        raw = base64.urlsafe_b64decode(ciphertext.encode())
        nonce, ct = raw[:12], raw[12:]
        return self.aesgcm.decrypt(nonce, ct, aad).decode()
```

#### 4.3.4 Key Management

Keys are never stored in configuration files. They are retrieved from:

1. **Environment variables** — `DG_ENCRYPTION_KEY` (dev only)
2. **HashiCorp Vault** — `vault://secret/dataguard/encryption-key`
3. **AWS KMS** — `kms://alias/dataguard-encryption-key`
4. **File** — `/run/secrets/encryption_key` (Docker secrets)

Key rotation is supported: the encryptor stores a key version alongside the
ciphertext: `ENC(v1:gAAAAA...)`. Decryption tries all active keys.

---

### 4.4 Classifier

The classifier determines the sensitivity level of each request, which drives
all downstream policy decisions (scrubbing rules, encryption requirements,
rate limits).

#### 4.4.1 Sensitivity Levels

| Level | Code | Description |
|-------|------|-------------|
| Public | `PUBLIC` | No PII, safe to forward as-is |
| Internal | `INTERNAL` | Business data, no PII — forward with audit |
| Confidential | `CONFIDENTIAL` | Contains PII — scrub before forwarding |
| Restricted | `RESTRICTED` | High-sensitivity PII (health, finance) — scrub + encrypt |
| Secret | `SECRET` | Must never leave the trust boundary — reject |

#### 4.4.2 Engine (`src/dataguard/classifier/engine.py`)

```python
"""Classifier engine — determines sensitivity level of requests."""

from enum import IntEnum

class SensitivityLevel(IntEnum):
    PUBLIC = 0
    INTERNAL = 1
    CONFIDENTIAL = 2
    RESTRICTED = 3
    SECRET = 4


class ClassifierEngine:
    """Orchestrates classification using rule-based and ML classifiers."""
    
    def __init__(self, config: ClassifierConfig):
        self.classifiers = []
        if config.rule_based.enabled:
            from dataguard.classifier.rule_based import RuleBasedClassifier
            self.classifiers.append(RuleBasedClassifier(config.rule_based))
        if config.ml.enabled:
            from dataguard.classifier.ml import MLClassifier
            self.classifiers.append(MLClassifier(config.ml))
    
    async def classify(self, request_body: dict) -> SensitivityLevel:
        """Classify the request. Returns the HIGHEST sensitivity found."""
        max_level = SensitivityLevel.PUBLIC
        for classifier in self.classifiers:
            level = await classifier.classify(request_body)
            max_level = max(max_level, level)
        return max_level
```

#### 4.4.3 Rule-Based Classifier (`src/dataguard/classifier/rule_based.py`)

Rules are defined in YAML configuration:

```yaml
classifier:
  rule_based:
    enabled: true
    rules:
      - name: "contains_ssn"
        pattern: "\\d{3}-\\d{2}-\\d{4}"
        level: CONFIDENTIAL
      - name: "contains_health_keyword"
        keywords: ["diagnosis", "prescription", "patient", "medical_record"]
        level: RESTRICTED
      - name: "contains_financial_keyword"
        keywords: ["account_number", "routing_number", "balance", "ssn"]
        level: RESTRICTED
      - name: "contains_secret_marker"
        keywords: ["[NEVER_SEND]", "CLASSIFIED", "TOP_SECRET"]
        level: SECRET
      - name: "contains_email"
        pattern: "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"
        level: CONFIDENTIAL
```

Each rule is evaluated against the flattened text of the request body. The
highest matching level wins.

#### 4.4.4 ML Classifier (`src/dataguard/classifier/ml.py`)

Optional NER-based classifier using spaCy:

```python
import spacy

class MLClassifier:
    def __init__(self, config):
        self.nlp = spacy.load(config.model)  # e.g. "en_core_web_lg"
        self.entity_map = {
            "PERSON": SensitivityLevel.CONFIDENTIAL,
            "SSN": SensitivityLevel.RESTRICTED,
            "MEDICAL_RECORD": SensitivityLevel.RESTRICTED,
            "EMAIL": SensitivityLevel.CONFIDENTIAL,
            "PHONE": SensitivityLevel.CONFIDENTIAL,
            "CREDIT_CARD": SensitivityLevel.RESTRICTED,
        }
    
    async def classify(self, body: dict) -> SensitivityLevel:
        text = self._flatten(body)
        doc = self.nlp(text)
        max_level = SensitivityLevel.PUBLIC
        for ent in doc.ents:
            if ent.label_ in self.entity_map:
                max_level = max(max_level, self.entity_map[ent.label_])
        return max_level
```

---

### 4.5 Rate Limiter

The rate limiter prevents abuse and cost overruns by enforcing per-tenant
request and token limits.

#### 4.5.1 Engine (`src/dataguard/ratelimiter/engine.py`)

```python
"""Rate limiter engine — token bucket with configurable backends."""

class RateLimiterEngine:
    def __init__(self, config: RateLimiterConfig):
        if config.backend == "redis":
            from dataguard.ratelimiter.redis_store import RedisStore
            self.store = RedisStore(config.redis)
        else:
            from dataguard.ratelimiter.memory_store import MemoryStore
            self.store = MemoryStore()
        self.buckets = self._build_buckets(config.limits)
    
    async def check(self, tenant_id: str, tokens: int = 1) -> RateLimitResult:
        """Check if request is within rate limit. Returns admit/deny + retry-after."""
        bucket = self.buckets.get(tenant_id, self.buckets["default"])
        return await bucket.consume(self.store, tenant_id, tokens)
```

#### 4.5.2 Token Bucket Algorithm (`src/dataguard/ratelimiter/token_bucket.py`)

```python
"""Token bucket rate limiting."""

@dataclass
class TokenBucket:
    rate: float          # tokens per second (refill rate)
    capacity: int        # max tokens (burst size)
    
    async def consume(
        self, store: RateLimitStore, key: str, tokens: int
    ) -> RateLimitResult:
        """Atomically consume tokens from the bucket."""
        state = await store.get_or_init(key, self.capacity)
        now = time.monotonic()
        elapsed = now - state.last_refill
        
        # Refill tokens
        state.tokens = min(
            self.capacity,
            state.tokens + elapsed * self.rate,
        )
        state.last_refill = now
        
        if state.tokens >= tokens:
            state.tokens -= tokens
            await store.set(key, state)
            return RateLimitResult(
                allowed=True,
                remaining=int(state.tokens),
                reset_at=now + (self.capacity - state.tokens) / self.rate,
            )
        else:
            retry_after = (tokens - state.tokens) / self.rate
            return RateLimitResult(
                allowed=False,
                remaining=0,
                retry_after=retry_after,
            )
```

#### 4.5.3 Redis Backend (`src/dataguard/ratelimiter/redis_store.py`)

The Redis backend uses Lua scripts for atomicity:

```lua
-- rate_limit.lua
local key = KEYS[1]
local rate = tonumber(ARGV[1])
local capacity = tonumber(ARGV[2])
local tokens = tonumber(ARGV[3])
local now = tonumber(ARGV[4])

local state = redis.call('HMGET', key, 'tokens', 'last_refill')
local current_tokens = tonumber(state[1]) or capacity
local last_refill = tonumber(state[2]) or now

local elapsed = now - last_refill
current_tokens = math.min(capacity, current_tokens + elapsed * rate)

if current_tokens >= tokens then
    current_tokens = current_tokens - tokens
    redis.call('HMSET', key, 'tokens', current_tokens, 'last_refill', now)
    redis.call('EXPIRE', key, math.ceil(capacity / rate))
    return {1, math.floor(current_tokens)}
else
    local retry_after = (tokens - current_tokens) / rate
    return {0, retry_after}
end
```

#### 4.5.4 Rate Limit Configuration

```yaml
ratelimiter:
  enabled: true
  backend: redis
  redis:
    url: "redis://redis:6379/0"
    key_prefix: "dg:ratelimit:"
  limits:
    default:
      rate: 10          # 10 requests/second
      capacity: 50      # burst of 50
      per_token_limit: 100000  # max tokens per minute
    tenant_premium:
      rate: 100
      capacity: 500
      per_token_limit: 1000000
  headers:
    enabled: true       # emit X-RateLimit-* headers
```

---

### 4.6 Audit Logger

The audit logger records every request and response to an append-only log for
compliance, debugging, and forensic analysis.

#### 4.6.1 Engine (`src/dataguard/audit/engine.py`)

```python
"""Audit engine — orchestrates audit event recording."""

class AuditEngine:
    def __init__(self, config: AuditConfig):
        self.writers = []
        if config.jsonl.enabled:
            from dataguard.audit.jsonl_writer import JsonlWriter
            self.writers.append(JsonlWriter(config.jsonl))
        if config.redis.enabled:
            from dataguard.audit.redis_writer import RedisStreamWriter
            self.writers.append(RedisStreamWriter(config.redis))
        if config.s3.enabled:
            from dataguard.audit.s3_writer import S3Writer
            self.writers.append(S3Writer(config.s3))
    
    async def log(self, event: AuditEvent) -> None:
        """Write audit event to all configured writers (fan-out)."""
        tasks = [writer.write(event) for writer in self.writers]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.warning(
                    "Audit write failed for writer %s: %s",
                    self.writers[i].__class__.__name__, result,
                )
```

#### 4.6.2 JSONL Writer (`src/dataguard/audit/jsonl_writer.py`)

Writes one JSON object per line with automatic rotation:

- **Rotation**: by size (default 100 MB) or time (daily)
- **Compression**: rotated files are gzip-compressed
- **Location**: `/var/log/dataguard/audit/` or configured path
- **Buffering**: async buffered writes (flush every 100 events or 1 second)

```python
class JsonlWriter:
    def __init__(self, config):
        self.path = Path(config.path)
        self.max_size = config.max_size_mb * 1024 * 1024
        self.buffer = []
        self.buffer_size = config.buffer_size  # default 100
        self._flush_task = None
    
    async def write(self, event: AuditEvent) -> None:
        line = event.model_dump_json()
        self.buffer.append(line)
        if len(self.buffer) >= self.buffer_size:
            await self._flush()
    
    async def _flush(self) -> None:
        async with aiofiles.open(self.path, mode="a") as f:
            await f.write("\n".join(self.buffer) + "\n")
        self.buffer.clear()
        await self._rotate_if_needed()
```

#### 4.6.3 Redis Stream Writer (`src/dataguard/audit/redis_writer.py`)

Writes audit events to a Redis Stream for real-time consumption by SIEM tools:

```python
class RedisStreamWriter:
    async def write(self, event: AuditEvent) -> None:
        await self.redis.xadd(
            name=self.stream_name,
            fields=event.to_flat_dict(),
            maxlen=self.maxlen,  # cap stream length
        )
```

#### 4.6.4 S3 Writer (`src/dataguard/audit/s3_writer.py`)

Writes to S3/MinIO for long-term archival:

- Uses `aiobotocore` for async S3 uploads
- Part-based multipart upload for large batches
- Supports SSE-S3 or SSE-KMS encryption at rest

---

## 5. API & Dashboard Endpoints

### 5.1 Proxy API

All proxy routes are served under `/v1/` and mirror the upstream LLM provider
APIs.

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/v1/chat/completions` | OpenAI-compatible chat |
| POST | `/v1/completions` | OpenAI-compatible completions |
| POST | `/v1/embeddings` | OpenAI-compatible embeddings |
| POST | `/v1/messages` | Anthropic-compatible messages |
| * | `/v1/{provider}/{path:path}` | Generic provider passthrough |

**Custom Headers:**

| Header | Direction | Purpose |
|--------|-----------|---------|
| `X-DG-Upstream` | Inbound | Explicitly select upstream provider |
| `X-DG-Tenant` | Inbound | Tenant identifier for rate limiting |
| `X-DG-Skip-Scrub` | Inbound | Bypass scrubbing (admin only) |
| `X-DG-Skip-Classify` | Inbound | Bypass classification (admin only) |
| `X-DG-Sensitivity` | Outbound | Resulting sensitivity level |
| `X-DG-Scrub-Count` | Outbound | Number of PII detections scrubbed |
| `X-RateLimit-Limit` | Outbound | Rate limit ceiling |
| `X-RateLimit-Remaining` | Outbound | Requests remaining |
| `X-RateLimit-Reset` | Outbound | Reset timestamp |

### 5.2 Management API

Served under `/api/` for configuration, inspection, and administrative tasks.

#### 5.2.1 Health & Readiness

```yaml
GET /api/health        # Liveness check
GET /api/ready        # Readiness check (verifies Redis, upstream connectivity)
GET /api/version      # Version info
```

**Response (health):**
```json
{
  "status": "healthy",
  "uptime_seconds": 3600,
  "version": "0.1.0"
}
```

**Response (ready):**
```json
{
  "status": "ready",
  "checks": {
    "redis": "ok",
    "audit_writer": "ok",
    "upstream_openai": "ok",
    "upstream_anthropic": "degraded"
  }
}
```

#### 5.2.2 Configuration

```yaml
GET    /api/config                  # Current effective configuration
GET    /api/config/schema           # JSON Schema for configuration
PUT    /api/config                  # Update configuration (hot reload)
POST   /api/config/reload           # Reload configuration from file
GET    /api/config/diff             # Show unsaved changes
```

#### 5.2.3 Scrubber Management

```yaml
GET    /api/scrubbers               # List registered scrubbers
GET    /api/scrubbers/{name}        # Get scrubber details
POST   /api/scrubbers/test          # Test scrubbing on sample text
```

**Test scrubbing request:**
```json
{
  "text": "My SSN is 123-45-6789 and email is user@example.com",
  "scrubbers": ["presidio", "regex"],
  "sensitivity": "CONFIDENTIAL"
}
```

**Response:**
```json
{
  "original": "My SSN is 123-45-6789 and email is user@example.com",
  "scrubbed": "My SSN is [REDACTED_SSN] and email is [REDACTED_EMAIL]",
  "detections": [
    {"entity": "SSN", "start": 10, "end": 21, "confidence": 0.85},
    {"entity": "EMAIL", "start": 32, "end": 48, "confidence": 0.95}
  ],
  "scrubbed_count": 2
}
```

#### 5.2.4 Classification

```yaml
POST   /api/classify                # Classify sample text
GET    /api/classify/rules          # List classification rules
POST   /api/classify/rules          # Add classification rule
DELETE /api/classify/rules/{name}   # Remove classification rule
```

#### 5.2.5 Rate Limiting

```yaml
GET    /api/ratelimit/limits                  # All rate limit configurations
GET    /api/ratelimit/limits/{tenant}         # Tenant-specific limits
PUT    /api/ratelimit/limits/{tenant}         # Update tenant limits
DELETE /api/ratelimit/limits/{tenant}         # Remove custom tenant limits
GET    /api/ratelimit/status/{tenant}         # Current bucket state
```

#### 5.2.6 Audit

```yaml
GET    /api/audit/events                     # Query audit events
GET    /api/audit/events/{event_id}          # Get specific event
GET    /api/audit/stats                      # Audit statistics
GET    /api/audit/export                     # Export audit log (JSONL/CSV)
```

**Query parameters for audit events:**
```
?start=2026-06-29T00:00:00Z
&end=2026-06-29T23:59:59Z
&tenant=acme
&sensitivity=CONFIDENTIAL,RESTRICTED
&status=scrubbed,rejected
&limit=100
&offset=0
```

#### 5.2.7 Encryption

```yaml
GET    /api/encryptor/keys                    # List key versions (no secrets)
POST   /api/encryptor/keys/rotate             # Rotate encryption key
GET    /api/encryptor/status                  # Encryptor status
POST   /api/encryptor/test                    # Test encrypt/decrypt round-trip
```

### 5.3 Dashboard

The dashboard is a Vue.js 3 SPA served by FastAPI at `/dashboard/`.

#### 5.3.1 Pages

| Route | Page | Purpose |
|-------|------|---------|
| `/dashboard/` | Overview | Real-time metrics, request rate, scrub stats |
| `/dashboard/requests` | Requests | Live request feed with scrubbing details |
| `/dashboard/audit` | Audit | Searchable audit log table |
| `/dashboard/policies` | Policies | Classification & scrubbing rule editor |
| `/dashboard/rate-limits` | Rate Limits | Rate limit per-tenant management |
| `/dashboard/encryption` | Encryption | Key management & rotation |
| `/dashboard/config` | Config | YAML configuration editor with validation |
| `/dashboard/health` | Health | Service health dashboard |

#### 5.3.2 Real-Time Updates

The dashboard uses Server-Sent Events (SSE) for live updates:

```
GET /api/events/stream?type=requests|audit|metrics
```

Events are pushed from the audit engine via an in-process broadcast channel
that fans out to all connected SSE clients.

### 5.4 Prometheus Metrics

Exposed at `:9090/metrics`:

```
# Request metrics
dg_requests_total{method, upstream, status, sensitivity}
dg_request_duration_seconds{method, upstream}
dg_request_body_size_bytes{method, upstream}

# Scrubber metrics
dg_scrub_total{entity_type, scrubber}
dg_scrub_duration_seconds{scrubber}
dg_scrub_detections_total{entity_type}

# Rate limiter metrics
dg_ratelimit_total{tenant, result}  # result: allowed|rejected
dg_ratelimit_tokens_remaining{tenant}

# Audit metrics
dg_audit_events_written_total{writer}
dg_audit_write_duration_seconds{writer}
dg_audit_write_errors_total{writer}

# Upstream metrics
dg_upstream_requests_total{provider, status}
dg_upstream_duration_seconds{provider}
dg_upstream_errors_total{provider, error_type}
```

---

## 6. Configuration Schema

### 6.1 Full YAML Schema

```yaml
# dataguard-fortress configuration
# All values shown are defaults

# ─── Server ─────────────────────────────────────────────
server:
  host: "0.0.0.0"
  port: 8000
  workers: 4                    # uvicorn workers
  loop: "uvloop"                # event loop implementation
  log_level: "info"
  access_log: true
  max_request_size: "10MB"      # reject larger requests
  request_timeout: 30           # seconds
  graceful_shutdown_timeout: 10

# ─── Authentication ─────────────────────────────────────
auth:
  enabled: true
  type: "api_key"               # api_key | jwt | mtls | none
  api_key:
    header: "X-API-Key"
    keys:                       # mapped in env/secrets, not here
      - "${DG_API_KEY_1}"
  jwt:
    issuer: "https://auth.example.com"
    audience: "dataguard-fortress"
    jwks_url: "https://auth.example.com/.well-known/jwks.json"
    algorithms: ["RS256"]
  mtls:
    ca_cert: "/etc/dataguard/mtls/ca.crt"
    client_cert_required: true

# ─── TLS ────────────────────────────────────────────────
tls:
  external:
    enabled: true
    cert_file: "/etc/dataguard/tls/server.crt"
    key_file: "/etc/dataguard/tls/server.key"
    ca_file: "/etc/dataguard/tls/ca.crt"
    min_version: "1.3"
    cipher_suites:
      - TLS_AES_256_GCM_SHA384
      - TLS_CHACHA20_POLY1305_SHA256
  internal:
    enabled: false

# ─── Upstreams ──────────────────────────────────────────
upstreams:
  default: "openai"
  timeout: 60
  max_connections: 1000
  max_keepalive: 100
  providers:
    - name: "openai"
      base_url: "https://api.openai.com"
      api_key: "${OPENAI_API_KEY}"
      headers:
        Authorization: "Bearer ${OPENAI_API_KEY}"
      rate_limit:
        rpm: 500                    # requests per minute
        tpm: 150000                 # tokens per minute
    - name: "anthropic"
      base_url: "https://api.anthropic.com"
      api_key: "${ANTHROPIC_API_KEY}"
      headers:
        x-api-key: "${ANTHROPIC_API_KEY}"
        anthropic-version: "2023-06-01"
      rate_limit:
        rpm: 1000
        tpm: 400000
    - name: "local"
      base_url: "http://localhost:11434"
      api_key: ""
      rate_limit:
        rpm: 10000
        tpm: 10000000

# ─── Classifier ─────────────────────────────────────────
classifier:
  enabled: true
  default_level: "INTERNAL"
  fail_closed: true             # reject on classification error
  rule_based:
    enabled: true
    rules:
      - name: "contains_ssn"
        pattern: "\\d{3}-\\d{2}-\\d{4}"
        level: "CONFIDENTIAL"
      - name: "contains_health_keyword"
        keywords: ["diagnosis", "prescription", "patient", "medical_record"]
        level: "RESTRICTED"
      - name: "contains_financial_keyword"
        keywords: ["account_number", "routing_number", "balance"]
        level: "RESTRICTED"
      - name: "contains_secret_marker"
        keywords: ["[NEVER_SEND]", "CLASSIFIED", "TOP_SECRET"]
        level: "SECRET"
      - name: "contains_email"
        pattern: "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"
        level: "CONFIDENTIAL"
      - name: "contains_phone"
        pattern: "\\+?1?\\s*\\(?\\d{3}\\)?[\\s.-]\\d{3}[\\s.-]\\d{4}"
        level: "CONFIDENTIAL"
  ml:
    enabled: false
    model: "en_core_web_lg"
    threshold: 0.7

# ─── Scrubber ───────────────────────────────────────────
scrubber:
  enabled: true
  fail_closed: true
  preserve_format: true         # keep original text structure
  replacements:
    default: "[REDACTED_{TYPE}]"
    custom:
      EMAIL: "[email_redacted]"
      PHONE: "[phone_redacted]"
  presidio:
    enabled: true
    language: "en"
    confidence_threshold: 0.5
    entities:
      - "CREDIT_CARD"
      - "EMAIL_ADDRESS"
      - "PHONE_NUMBER"
      - "US_SSN"
      - "US_PASSPORT"
      - "IP_ADDRESS"
      - "PERSON"
      - "LOCATION"
    custom_recognizers: []     # paths to custom Presidio recognizers
  regex:
    enabled: true
    patterns:
      - name: "aws_access_key"
        pattern: "AKIA[0-9A-Z]{16}"
        replacement: "[REDACTED_AWS_KEY]"
        level: "RESTRICTED"
      - name: "api_key_generic"
        pattern: "(sk-|pk-|key-)[a-zA-Z0-9]{20,}"
        replacement: "[REDACTED_API_KEY]"
        level: "RESTRICTED"
  custom: []                   # entry point names for custom scrubbers

# ─── Encryptor ──────────────────────────────────────────
encryptor:
  enabled: true
  provider: "aes_gcm"            # fernet | aes_gcm
  key_source: "env"              # env | vault | kms | file
  key_env_var: "DG_ENCRYPTION_KEY"
  key_version: 1
  fields:                        # JSONPath expressions of fields to encrypt
    - "$.messages[*].content"    # encrypt all message content
    - "$.system"                 # encrypt system prompt
  encrypt_on_level:              # only encrypt when sensitivity >= threshold
    threshold: "RESTRICTED"
  decrypt_response: true         # auto-decrypt responses

# ─── Rate Limiter ───────────────────────────────────────
ratelimiter:
  enabled: true
  backend: "redis"               # redis | memory
  redis:
    url: "redis://localhost:6379/0"
    key_prefix: "dg:ratelimit:"
    socket_timeout: 5
  limits:
    default:
      rate: 10
      capacity: 50
      per_minute: 600
      per_token_per_minute: 100000
    authenticated:
      rate: 50
      capacity: 200
      per_minute: 3000
      per_token_per_minute: 500000
  headers:
    enabled: true

# ─── Audit ──────────────────────────────────────────────
audit:
  enabled: true
  include_request_body: true     # log full request body
  include_response_body: false   # log response body (expensive)
  redact_in_log: true            # redact PII in audit log itself
  jsonl:
    enabled: true
    path: "/var/log/dataguard/audit/audit.jsonl"
    max_size_mb: 100
    rotation: "daily"            # daily | size | hourly
    compression: "gzip"
    buffer_size: 100
    flush_interval_seconds: 1
  redis:
    enabled: false
    url: "redis://localhost:6379/1"
    stream_name: "dg:audit"
    maxlen: 10000
  s3:
    enabled: false
    bucket: "dataguard-audit"
    prefix: "audit/"
    region: "us-east-1"
    kms_key_id: null
    batch_size: 1000
    upload_interval_seconds: 60

# ─── Dashboard ──────────────────────────────────────────
dashboard:
  enabled: true
  host: "0.0.0.0"
  port: 8001
  auth:
    enabled: true
    type: "jwt"
  cors:
    origins: ["http://localhost:3000"]
    methods: ["GET", "POST", "PUT", "DELETE"]
    max_age: 3600

# ─── Metrics ────────────────────────────────────────────
metrics:
  enabled: true
  port: 9090
  path: "/metrics"
  namespace: "dg"

# ─── Logging ────────────────────────────────────────────
logging:
  level: "info"
  format: "json"                 # json | text
  output: "stdout"               # stdout | file
  file_path: "/var/log/dataguard/app.log"
  max_size_mb: 50
  backup_count: 5
```

### 6.2 Schema Validation

Configuration is validated at startup using Pydantic v2:

```python
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings

class ServerConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = Field(default=8000, ge=1, le=65535)
    workers: int = Field(default=4, ge=1, le=64)
    loop: Literal["asyncio", "uvloop"] = "uvloop"
    log_level: Literal["debug", "info", "warning", "error"] = "info"
    max_request_size: str = "10MB"
    request_timeout: int = Field(default=30, ge=1)

class AppConfig(BaseSettings):
    server: ServerConfig = ServerConfig()
    auth: AuthConfig = AuthConfig()
    tls: TlsConfig = TlsConfig()
    upstreams: UpstreamsConfig = UpstreamsConfig()
    classifier: ClassifierConfig = ClassifierConfig()
    scrubber: ScrubberConfig = ScrubberConfig()
    encryptor: EncryptorConfig = EncryptorConfig()
    ratelimiter: RateLimiterConfig = RateLimiterConfig()
    audit: AuditConfig = AuditConfig()
    dashboard: DashboardConfig = DashboardConfig()
    metrics: MetricsConfig = MetricsConfig()
    logging: LoggingConfig = LoggingConfig()
    
    model_config = SettingsConfigDict(
        yaml_file="config/default.yaml",
        env_prefix="DG_",
        env_nested_delimiter="__",
    )
```

### 6.3 Environment Variable Overrides

Every config value can be overridden with environment variables:

```
DG_SERVER__PORT=8080
DG_UPSTREAMS__DEFAULT=anthropic
DG_SCRUBBER__PRESIDIO__CONFIDENCE_THRESHOLD=0.7
DG_RATELIMITER__BACKEND=memory
DG_AUDIT__JSONL__PATH=/custom/path/audit.jsonl
DG_ENCRYPTION_KEY=gAAAAAB...   # (special, not part of main config)
```

---

## 7. Docker & Docker-Compose Setup

### 7.1 Dockerfile

```dockerfile
# ─── Build stage ─────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build dependencies
COPY pyproject.toml ./
RUN pip install --no-cache-dir build && \
    pip install --no-cache-dir .

# ─── Runtime stage ───────────────────────────────────────
FROM python:3.12-slim AS runtime

# Security: create non-root user
RUN groupadd -r dataguard && \
    useradd -r -g dataguard -d /app -s /sbin/nologin dataguard

WORKDIR /app

# Install runtime dependencies only
COPY --from=builder /build/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -rf /tmp/*

# Copy application code
COPY src/ src/
COPY config/ config/

# Create audit log directory
RUN mkdir -p /var/log/dataguard/audit && \
    chown -R dataguard:dataguard /var/log/dataguard

# Security hardening
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl=7.88.* && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

# Switch to non-root user
USER dataguard

EXPOSE 8000 8001 9090

ENV DG_SERVER__WORKERS=4 \
    DG_SERVER__LOOP=uvloop \
    DG_LOGGING__FORMAT=json

ENTRYPOINT ["python", "-m", "dataguard.main"]
CMD ["--config", "config/default.yaml"]
```

### 7.2 Dockerfile.slim (minimal for CI)

```dockerfile
FROM python:3.12-alpine

WORKDIR /app
COPY --from=builder /build/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -rf /tmp/*
COPY src/ src/
COPY config/ config/

EXPOSE 8000
ENTRYPOINT ["python", "-m", "dataguard.main"]
```

### 7.3 docker-compose.yml

```yaml
version: "3.9"

services:
  # ─── DataGuard Fortress Proxy ──────────────────────
  proxy:
    build:
      context: .
      dockerfile: docker/Dockerfile
    container_name: dg-proxy
    restart: unless-stopped
    ports:
      - "8000:8000"
      - "8001:8001"
      - "9090:9090"
    environment:
      DG_SERVER__WORKERS: 4
      DG_RATELIMITER__BACKEND: redis
      DG_RATELIMITER__REDIS__URL: redis://redis:6379/0
      DG_AUDIT__JSONL__PATH: /var/log/dataguard/audit/audit.jsonl
      DG_AUDIT__REDIS__ENABLED: "true"
      DG_AUDIT__REDIS__URL: redis://redis:6379/1
      DG_ENCRYPTION_KEY: ${DG_ENCRYPTION_KEY}
      OPENAI_API_KEY: ${OPENAI_API_KEY:-}
      ANTHROPIC_API_KEY: ${ANTHROPIC_API_KEY:-}
    volumes:
      - audit-logs:/var/log/dataguard/audit
      - ./config:/app/config:ro
      - ./tls:/etc/dataguard/tls:ro
    depends_on:
      redis:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/api/health"]
      interval: 30s
      timeout: 5s
      retries: 3
    networks:
      - dmz
      - app

  # ─── Redis ─────────────────────────────────────────
  redis:
    image: redis:7-alpine
    container_name: dg-redis
    restart: unless-stopped
    command: >
      redis-server
      --maxmemory 256mb
      --maxmemory-policy allkeys-lru
      --appendonly yes
    ports:
      - "6379:6379"
    volumes:
      - redis-data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 3s
      retries: 3
    networks:
      - app

  # ─── MinIO (S3-compatible audit storage) ───────────
  minio:
    image: minio/minio:latest
    container_name: dg-minio
    restart: unless-stopped
    command: server /data --console-address ":9001"
    ports:
      - "9000:9000"
      - "9001:9001"
    environment:
      MINIO_ROOT_USER: ${MINIO_ACCESS_KEY:-minioadmin}
      MINIO_ROOT_PASSWORD: ${MINIO_SECRET_KEY:-minioadmin}
    volumes:
      - minio-data:/data
    networks:
      - app

  # ─── Prometheus ────────────────────────────────────
  prometheus:
    image: prom/prometheus:latest
    container_name: dg-prometheus
    restart: unless-stopped
    ports:
      - "9091:9090"
    volumes:
      - ./monitoring/prometheus.yml:/etc/prometheus/prometheus.yml:ro
    networks:
      - app

  # ─── Grafana ───────────────────────────────────────
  grafana:
    image: grafana/grafana:latest
    container_name: dg-grafana
    restart: unless-stopped
    ports:
      - "3000:3000"
    environment:
      GF_SECURITY_ADMIN_PASSWORD: ${GRAFANA_PASSWORD:-admin}
      GF_USERS_ALLOW_SIGN_UP: "false"
    volumes:
      - grafana-data:/var/lib/grafana
    depends_on:
      - prometheus
    networks:
      - app

  # ─── nginx (TLS termination & LB) ─────────────────
  nginx:
    image: nginx:alpine
    container_name: dg-nginx
    restart: unless-stopped
    ports:
      - "443:443"
      - "80:80"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./tls:/etc/nginx/tls:ro
    depends_on:
      - proxy
    networks:
      - dmz

volumes:
  audit-logs:
  redis-data:
  minio-data:
  grafana-data:

networks:
  dmz:
    driver: bridge
    ipam:
      config:
        - subnet: 10.0.1.0/24
  app:
    driver: bridge
    ipam:
      config:
        - subnet: 10.0.2.0/24
```

### 7.4 nginx Configuration

```nginx
upstream dataguard {
    least_conn;
    server proxy:8000;
}

server {
    listen 80;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name dataguard.example.com;

    ssl_certificate     /etc/nginx/tls/server.crt;
    ssl_certificate_key /etc/nginx/tls/server.key;
    ssl_protocols       TLSv1.3;
    ssl_ciphers         TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;

    # Security headers
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Content-Security-Policy "default-src 'self'" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Proxy routes
    location /v1/ {
        proxy_pass http://dataguard;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_buffering off;
        proxy_read_timeout 60s;
    }

    # Dashboard
    location /dashboard/ {
        proxy_pass http://dataguard:8001/dashboard/;
    }

    # Management API
    location /api/ {
        proxy_pass http://dataguard;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

---

## 8. CI/CD Pipeline (GitHub Actions)

### 8.1 CI Workflow (`.github/workflows/ci.yml`)

```yaml
name: CI

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

concurrency:
  group: ci-${{ github.ref }}
  cancel-in-progress: true

jobs:
  # ─── Lint & Format ────────────────────────────────
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Install dev dependencies
        run: pip install -e ".[dev]"
      - name: Ruff check
        run: ruff check src/ tests/
      - name: Ruff format check
        run: ruff format --check src/ tests/
      - name: MyPy
        run: mypy src/ --strict

  # ─── Unit Tests ───────────────────────────────────
  unit-tests:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ["3.12", "3.13"]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}
      - name: Install dependencies
        run: pip install -e ".[test]"
      - name: Run unit tests
        run: |
          pytest tests/unit/ \
            --cov=dataguard \
            --cov-report=xml \
            --cov-report=term-missing \
            --junitxml=test-results.xml \
            -n auto
      - uses: actions/upload-artifact@v4
        with:
          name: test-results-${{ matrix.python-version }}
          path: test-results.xml
      - name: Upload coverage
        uses: codecov/codecov-action@v4
        with:
          file: coverage.xml

  # ─── Integration Tests ────────────────────────────
  integration-tests:
    runs-on: ubuntu-latest
    needs: [unit-tests]
    services:
      redis:
        image: redis:7-alpine
        ports:
          - 6379:6379
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Install dependencies
        run: pip install -e ".[test]"
      - name: Run integration tests
        env:
          DG_RATELIMITER__REDIS__URL: redis://localhost:6379/0
        run: |
          pytest tests/integration/ \
            --timeout=60 \
            -n auto

  # ─── E2E Tests ────────────────────────────────────
  e2e-tests:
    runs-on: ubuntu-latest
    needs: [integration-tests]
    steps:
      - uses: actions/checkout@v4
      - name: Build Docker image
        run: docker build -t dataguard-fortress:test -f docker/Dockerfile .
      - name: Start test stack
        run: docker compose -f docker-compose.yml -f docker-compose.test.yml up -d
      - name: Wait for proxy
        run: |
          for i in $(seq 1 30); do
            curl -sf http://localhost:8000/api/health && break
            sleep 2
          done
      - name: Run E2E tests
        run: |
          pip install -e ".[test]"
          pytest tests/e2e/ --base-url=http://localhost:8000
      - name: Collect logs
        if: always()
        run: docker compose logs > docker-logs.txt
      - name: Teardown
        if: always()
        run: docker compose down -v

  # ─── Docker Build ─────────────────────────────────
  docker:
    runs-on: ubuntu-latest
    needs: [lint, unit-tests]
    permissions:
      packages: write
    steps:
      - uses: actions/checkout@v4
      - uses: docker/setup-buildx-action@v3
      - uses: docker/build-push-action@v5
        with:
          context: .
          file: docker/Dockerfile
          push: ${{ github.event_name == 'push' && github.ref == 'refs/heads/main' }}
          tags: |
            ghcr.io/${{ github.repository }}:latest
            ghcr.io/${{ github.repository }}:${{ github.sha }}
          cache-from: type=gha
          cache-to: type=gha,mode=max
```

### 8.2 Security Workflow (`.github/workflows/security.yml`)

```yaml
name: Security

on:
  push:
    branches: [main]
  schedule:
    - cron: "0 6 * * 1"  # Weekly Monday 6AM UTC
  pull_request:
    branches: [main]

jobs:
  # ─── Dependency Audit ─────────────────────────────
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: pip-audit
        run: |
          pip install pip-audit
          pip-audit --strict --desc
      - name: Safety check
        run: |
          pip install safety
          safety check --full-report

  # ─── SAST ─────────────────────────────────────────
  sast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Bandit
        run: |
          pip install bandit
          bandit -r src/ -f json -o bandit-report.json --severity-level medium
      - name: Semgrep
        uses: returntocorp/semgrep-action@v1
        with:
          config: >-
            p/python
            p/security-audit
            p/secrets

  # ─── Secret Scanning ──────────────────────────────
  secrets:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: trufflesecurity/trufflehog@main
        with:
          extra_args: --only-verified

  # ─── Container Scan ───────────────────────────────
  container-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build image
        run: docker build -t dataguard-fortress:scan -f docker/Dockerfile .
      - name: Trivy scan
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: dataguard-fortress:scan
          severity: "CRITICAL,HIGH"
          exit-code: "1"
```

### 8.3 Release Workflow (`.github/workflows/release.yml`)

```yaml
name: Release

on:
  push:
    tags: ["v*"]

jobs:
  release:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      packages: write
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Build package
        run: |
          pip install build
          python -m build

      - name: Publish to PyPI
        uses: pypa/gh-action-pypi-publish@release/v1
        with:
          password: ${{ secrets.PYPI_TOKEN }}

      - name: Build & push Docker image
        uses: docker/build-push-action@v5
        with:
          context: .
          file: docker/Dockerfile
          push: true
          tags: |
            ghcr.io/${{ github.repository }}:${{ github.ref_name }}
            ghcr.io/${{ github.repository }}:latest
          build-args: |
            VERSION=${{ github.ref_name }}

      - name: Create GitHub Release
        uses: softprops/action-gh-release@v2
        with:
          generate_release_notes: true
          files: dist/*
```

---

## 9. Security Model

### 9.1 Threat Model

We use the STRIDE model to identify threats at each trust boundary:

| ID | Threat | STRIDE | Trust Boundary | Impact | Likelihood |
|----|--------|--------|----------------|--------|------------|
| T1 | Attacker sends PII-laden prompt to leak via proxy | Information Disclosure | Client → Proxy | High | High |
| T2 | Compromised API key used to bypass scrubbing | Elevation of Privilege | Client → Proxy | High | Medium |
| T3 | Attacker extracts encryption keys from proxy memory | Information Disclosure | Within Proxy | Critical | Low |
| T4 | Man-in-the-middle intercepts proxy ↔ upstream traffic | Tampering, Information Disclosure | Proxy → Upstream | High | Low |
| T5 | Attacker floods proxy to exhaust rate limit (DoS) | Denial of Service | Client → Proxy | Medium | High |
| T6 | Malicious upstream injects content into responses | Tampering, Spoofing | Proxy ← Upstream | Medium | Low |
| T7 | Audit log tampering or deletion | Tampering, Repudiation | Within Proxy | High | Low |
| T8 | Attadder gains shell access via container escape | Elevation of Privilege | Container | Critical | Very Low |
| T9 | Side-channel: timing attack on scrubber | Information Disclosure | Within Proxy | Low | Very Low |
| T10 | Attacker bypasses classification to send SECRET data | Information Disclosure | Client → Proxy | Critical | Low |
| T11 | Injection via malformed JSON in request body | Tampering | Client → Proxy | Medium | Medium |
| T12 | Attacker uses proxy as open redirect to arbitrary hosts | Spoofing | Client → Proxy | Medium | Medium |

### 9.2 Defense-in-Depth

#### 9.2.1 Network Layer

| Defense | Mitigates | Implementation |
|---------|-----------|----------------|
| TLS 1.3 everywhere | T4 | nginx terminates TLS; proxy → upstream enforces HTTPS |
| Egress firewall | T12 | Only whitelisted upstream hosts allowed |
| Network segmentation | T8 | Separate DMZ / App / Management VLANs |
| mTLS for internal | T4 | Optional mTLS between proxy instances |

#### 9.2.2 Authentication & Authorization

| Defense | Mitigates | Implementation |
|---------|-----------|----------------|
| API key validation | T2 | Constant-time comparison; keys stored hashed (argon2) |
| JWT with RS256 | T2 | JWKS rotation; short-lived tokens (15 min) |
| mTLS (optional) | T2 | Client certificates for high-security deployments |
| RBAC | T2 | Admin vs. user vs. read-only roles |
| IP allowlisting | T5, T12 | Optional IP-based access control |

#### 9.2.3 Data Protection

| Defense | Mitigates | Implementation |
|---------|-----------|----------------|
| Fail-closed classification | T10 | Errors → reject, never forward |
| Fail-closed scrubbing | T1 | Errors → reject, never forward unscrubbed data |
| Field-level encryption | T3 | Keys in Vault/KMS, never in config/memory long-term |
| Key rotation | T3 | Versioned keys; automatic rotation every 90 days |
| Memory zeroization | T3 | Sensitive buffers wiped after use (ctypes.memset) |
| No request body logging by default | T3 | Audit logs contain metadata only unless explicitly enabled |
| PII redaction in audit logs | T7 | Even audit logs are scrubbed of PII |

#### 9.2.4 Rate Limiting & DoS

| Defense | Mitigates | Implementation |
|---------|-----------|----------------|
| Token bucket rate limiting | T5 | Per-tenant, per-key, global limits |
| Request size limiting | T5 | `server.max_request_size: 10MB` |
| Connection limiting | T5 | `upstreams.max_connections: 1000` |
| Timeout enforcement | T5 | All I/O operations have timeouts |
| Slowloris protection | T5 | nginx `client_body_timeout` |

#### 9.2.5 Application Security

| Defense | Mitigates | Implementation |
|---------|-----------|----------------|
| Input validation (Pydantic) | T11 | All inputs validated against strict schemas |
| Output encoding | T6 | Headers sanitized; no HTML rendering in proxy |
| No eval/exec | T11 | No dynamic code execution in any path |
| Dependency pinning | T8 | Exact versions + hashes in requirements |
| Container non-root | T8 | `USER dataguard` in Dockerfile |
| Read-only filesystem | T8 | `/app` mounted read-only except logs |
| Security headers | T6 | HSTS, CSP, X-Frame-Options via nginx |
| CORS restriction | T6 | Strict origin allowlisting |

#### 9.2.6 Audit & Accountability

| Defense | Mitigates | Implementation |
|---------|-----------|----------------|
| Append-only audit log | T7 | JSONL files; write-only directory permissions |
| Log integrity (hash chain) | T7 | Each event includes SHA-256 of previous event |
| S3 immutable storage | T7 | Object Lock / WORM for audit archives |
| Separate audit volume | T7 | Docker volume mounted read-only after creation |
| Real-time SIEM feed | T7 | Redis Stream → Splunk / Elastic / Datadog |

### 9.3 Security Headers

All outbound responses include:

```
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
Content-Security-Policy: default-src 'none'; frame-ancestors 'none'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
```

### 9.4 Secrets Management

Secrets are NEVER stored in:
- Configuration files
- Environment variables in production (except for dev/testing)
- Container images
- Git repository

In production, secrets are sourced from:

| Secret | Source | Rotation |
|--------|--------|----------|
| API keys (upstream) | HashiCorp Vault / AWS Secrets Manager | 90 days |
| Encryption key | Vault transit engine / AWS KMS | 90 days |
| JWT signing key | Vault / OIDC provider | 24 hours |
| Dashboard auth | OIDC provider | N/A |
| Redis auth | Vault | 90 days |

### 9.5 Compliance Mapping

| Requirement | DataGuard Feature |
|-------------|-------------------|
| GDPR Art. 25 (Data Protection by Design) | Automatic PII scrubbing |
| GDPR Art. 32 (Security of Processing) | Encryption, access control, audit logs |
| HIPAA §164.312(a) (Access Control) | API key / JWT auth, RBAC |
| HIPAA §164.312(b) (Audit Controls) | JSONL audit trail with hash chain |
| HIPAA §164.312(e) (Transmission Security) | TLS 1.3, field-level encryption |
| SOC 2 CC6.1 (Logical Access) | Auth, RBAC, fail-closed design |
| SOC 2 CC7.2 (Monitoring) | Metrics, audit, health checks |
| ISO 27001 A.10.1.1 (Encryption) | AES-256-GCM, TLS 1.3 |
| PCI DSS 3.4 (Cryptography) | AES-256-GCM for card data |

---

## 10. Performance Targets

### 10.1 Latency Budget

The proxy MUST add **< 5 ms** overhead at the p99 percentile on the critical
path (excluding upstream round-trip time).

| Stage | Target (p50) | Target (p99) | Notes |
|-------|-------------|-------------|-------|
| Auth | 0.1 ms | 0.3 ms | API key: constant-time compare; JWT: cached JWKS |
| Classification (rule) | 0.2 ms | 0.5 ms | Regex evaluation on flattened text |
| Classification (ML) | 2.0 ms | 4.0 ms | spaCy NER (optional, cached models) |
| Scrubbing (regex) | 0.3 ms | 0.8 ms | Pattern matching on text |
| Scrubbing (Presidio) | 1.5 ms | 3.0 ms | NLP analysis (optional) |
| Encryption | 0.05 ms | 0.1 ms | AES-256-GCM hardware-accelerated |
| Rate limit check | 0.1 ms | 0.3 ms | Redis Lua script |
| Audit log (buffered) | 0.01 ms | 0.05 ms | Async buffered write |
| **Total (regex path)** | **~0.8 ms** | **~2.1 ms** | Production default |
| **Total (Presidio path)** | **~4.0 ms** | **~8.3 ms** | May exceed 5ms with ML |

### 10.2 Throughput Targets

| Metric | Target | Notes |
|--------|--------|-------|
| Requests per second | **10,000 req/s** | Single instance, regex-only path |
| Requests per second (Presidio) | **2,000 req/s** | NLP-bound |
| Concurrent connections | 10,000 | httpx connection pool |
| Audit events per second | 50,000 | Buffered JSONL writes |
| Rate limit operations/s | 100,000 | Redis-backed Lua scripts |

### 10.3 Resource Limits

| Resource | Default | Maximum | Notes |
|----------|---------|---------|-------|
| Memory per instance | 256 MB | 1 GB | Configurable via Docker limits |
| CPU per instance | 1 core | 4 cores | Classification is CPU-bound |
| Max request body | 10 MB | 50 MB | `server.max_request_size` |
| Max response body | 50 MB | 200 MB | Streaming responses not counted |
| Redis memory | 256 MB | 2 GB | Rate limit + audit state |
| Audit log file | 100 MB | 1 GB | Per file, before rotation |

### 10.4 Optimization Strategies

1. **uvloop** — Replace asyncio default event loop with uvloop (2-4x faster)
2. **Regex compilation** — All patterns compiled at startup, never re-compiled
3. **Model caching** — spaCy / Presidio models loaded once, reused across requests
4. **Connection pooling** — httpx AsyncClient with keep-alive connections to upstreams
5. **Buffered audit writes** — Batch 100 events before flushing to disk
6. **Redis pipelining** — Batch rate limit checks when processing multiple requests
7. **Zero-copy** — Avoid unnecessary serialization/deserialization of request bodies
8. **Lazy classification** — Skip ML classification if rule-based already returns RESTRICTED or SECRET
9. **Parallel scrubbing** — Run multiple regex scrubbers concurrently with `asyncio.gather`

### 10.5 Benchmarking

```python
# benchmarks/bench_proxy.py
import pytest
from pytest-benchmark import BenchmarkFixture

@pytest.mark.benchmark(group="scrubber")
def test_regex_scrub_benchmark(benchmark: BenchmarkFixture):
    scrubber = RegexScrubber(default_config)
    text = "My SSN is 123-45-6789 and email is user@example.com"
    result = benchmark(scrubber.detect_and_redact, text)
    assert result.count == 2

@pytest.mark.benchmark(group="classification")
def test_rule_classify_benchmark(benchmark: BenchmarkFixture):
    classifier = RuleBasedClassifier(default_config)
    body = {"messages": [{"role": "user", "content": "Hello world"}]}
    result = benchmark(classifier.classify, body)
    assert result == SensitivityLevel.PUBLIC
```

Load testing with Locust:

```python
# benchmarks/locustfile.py
from locust import HttpUser, task, between

class ProxyUser(HttpUser):
    wait_time = between(0.1, 0.5)
    
    @task
    def chat_completion(self):
        self.client.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-4",
                "messages": [
                    {"role": "user", "content": "Hello, my email is test@example.com"}
                ],
            },
            headers={
                "Authorization": "Bearer test-key",
                "X-DG-Upstream": "mock",
            },
        )
```

### 10.6 SLA Targets

| Metric | SLO | SLA | Measurement Window |
|--------|-----|-----|--------------------|
| Availability | 99.9% | 99.5% | Monthly |
| Proxy latency (p99) | < 5 ms | < 10 ms | 5-minute rolling |
| Scrub accuracy | > 99% | > 98% | Quarterly audit |
| Audit completeness | 100% | 99.99% | Monthly |
| False positive rate | < 1% | < 5% | Quarterly audit |

---

## 11. Audit Log Data Schema

### 11.1 Event Structure

Every audit event is a single JSON object written to a JSONL file. The schema
uses Pydantic for validation.

```python
from pydantic import BaseModel, Field
from datetime import datetime
from enum import Enum

class AuditEventType(str, Enum):
    REQUEST_RECEIVED = "request_received"
    REQUEST_CLASSIFIED = "request_classified"
    REQUEST_SCRUBBED = "request_scrubbed"
    REQUEST_ENCRYPTED = "request_encrypted"
    REQUEST_RATE_LIMITED = "request_rate_limited"
    REQUEST_FORWARDED = "request_forwarded"
    RESPONSE_RECEIVED = "response_received"
    RESPONSE_DECRYPTED = "response_decrypted"
    RESPONSE_RETURNED = "response_returned"
    REQUEST_REJECTED = "request_rejected"
    REQUEST_ERROR = "request_error"

class AuditEvent(BaseModel):
    """Single audit event — one line in the JSONL log."""
    
    # ─── Core fields (always present) ───────────────
    event_id: str = Field(..., description="UUID v7 (time-sortable)")
    timestamp: datetime = Field(..., description="ISO 8601 UTC timestamp")
    event_type: AuditEventType
    trace_id: str = Field(..., description="Distributed trace ID")
    request_id: str = Field(..., description="Per-request unique ID")
    
    # ─── Request context ────────────────────────────
    tenant_id: str | None = None
    client_ip: str = Field(None, description="Client IP (anonymized if configured)")
    method: str = Field(..., description="HTTP method")
    path: str = Field(..., description="Request path")
    upstream: str | None = Field(None, description="Target upstream name")
    
    # ─── Classification ─────────────────────────────
    sensitivity: str | None = Field(None, description="PUBLIC|INTERNAL|CONFIDENTIAL|RESTRICTED|SECRET")
    classifier: str | None = Field(None, description="Classifier used (rule_based|ml)")
    classification_duration_ms: float | None = None
    
    # ─── Scrubbing ──────────────────────────────────
    scrubbed: bool = False
    scrub_count: int = 0
    scrub_entities: list[str] = Field(default_factory=list)
    scrubber: str | None = None
    scrub_duration_ms: float | None = None
    
    # ─── Encryption ─────────────────────────────────
    encrypted: bool = False
    encrypted_fields: list[str] = Field(default_factory=list)
    encryption_duration_ms: float | None = None
    
    # ─── Rate limiting ──────────────────────────────
    rate_limited: bool = False
    rate_limit_remaining: int | None = None
    rate_limitRetry_after: float | None = None
    
    # ─── Response ────────────────────────────────────
    status_code: int | None = None
    response_size_bytes: int | None = None
    upstream_latency_ms: float | None = None
    
    # ─── Error ──────────────────────────────────────
    error_type: str | None = None
    error_message: str | None = None
    
    # ─── Integrity ──────────────────────────────────
    previous_event_hash: str = Field(
        ..., description="SHA-256 of previous event (hash chain)"
    )
    
    model_config = {"json_schema_extra": {"example": {
        "event_id": "01923456-7890-7abc-def0-1234567890ab",
        "timestamp": "2026-06-29T14:30:00.123456Z",
        "event_type": "request_scrubbed",
        "trace_id": "abc123def456",
        "request_id": "req-xyz-789",
        "tenant_id": "acme-corp",
        "client_ip": "203.0.113.42",
        "method": "POST",
        "path": "/v1/chat/completions",
        "upstream": "openai",
        "sensitivity": "CONFIDENTIAL",
        "classifier": "rule_based",
        "classification_duration_ms": 0.23,
        "scrubbed": True,
        "scrub_count": 2,
        "scrub_entities": ["EMAIL_ADDRESS", "PHONE_NUMBER"],
        "scrubber": "presidio",
        "scrub_duration_ms": 1.45,
        "encrypted": False,
        "encrypted_fields": [],
        "encryption_duration_ms": None,
        "rate_limited": False,
        "rate_limit_remaining": 48,
        "status_code": 200,
        "response_size_bytes": 1024,
        "upstream_latency_ms": 230.5,
        "previous_event_hash": "a3f2b8c...",
    }}}
```

### 11.2 JSONL File Format

```
{"event_id":"0192...","timestamp":"2026-06-29T14:30:00.123456Z","event_type":"request_received",...}
{"event_id":"0192...","timestamp":"2026-06-29T14:30:00.124000Z","event_type":"request_classified",...}
{"event_id":"0192...","timestamp":"2026-06-29T14:30:00.125500Z","event_type":"request_scrubbed",...}
{"event_id":"0192...","timestamp":"2026-06-29T14:30:00.126000Z","event_type":"request_forwarded",...}
{"event_id":"0192...","timestamp":"2026-06-29T14:30:00.360000Z","event_type":"response_received",...}
{"event_id":"0192...","timestamp":"2026-06-29T14:30:00.361000Z","event_type":"response_returned",...}
```

### 11.3 Hash Chain Integrity

Each event includes the SHA-256 hash of the previous event's canonical JSON,
creating an append-only hash chain that detects tampering:

```python
import hashlib
import json

def compute_event_hash(event: dict) -> str:
    """Compute canonical SHA-256 hash of an audit event."""
    canonical = json.dumps(event, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()

def verify_chain(events: list[dict]) -> bool:
    """Verify the integrity of the entire hash chain."""
    for i in range(1, len(events)):
        expected = compute_event_hash(events[i - 1])
        actual = events[i]["previous_event_hash"]
        if expected != actual:
            return False
    return True
```

### 11.4 Rotation & Compression

```
audit/
├── audit-2026-06-29.jsonl          # Today's active file
├── audit-2026-06-28.jsonl.gz       # Yesterday's compressed
├── audit-2026-06-27.jsonl.gz       # Two days ago
└── ...
```

Rotation rules:
- **Daily**: New file at midnight UTC
- **Size-based**: New file when current exceeds `max_size_mb`
- **Compression**: Previous file gzip-compressed after rotation
- **Retention**: Configurable; default 90 days

### 11.5 Querying Audit Events

Audit events can be queried via the Management API or directly from JSONL files:

```bash
# Using jq for ad-hoc queries
cat audit.jsonl | jq 'select(.sensitivity == "CONFIDENTIAL") | {timestamp, tenant_id, scrub_count}'

# Count scrubbed requests per tenant
cat audit.jsonl | jq -s 'group_by(.tenant_id) | map({tenant: .[0].tenant_id, count: length})'

# Find all rejected requests
cat audit.jsonl | jq 'select(.event_type == "request_rejected")'
```

---

## 12. Testing Strategy

### 12.1 Test Architecture

```
tests/
├── conftest.py              # Shared fixtures
├── unit/                    # No external dependencies
│   ├── test_scrubber/
│   │   ├── test_engine.py
│   │   ├── test_presidio.py
│   │   └── test_regex.py
│   ├── test_encryptor/
│   │   ├── test_engine.py
│   │   ├── test_fernet.py
│   │   └── test_aes_gcm.py
│   ├── test_classifier/
│   │   ├── test_engine.py
│   │   ├── test_rule_based.py
│   │   └── test_ml.py
│   ├── test_ratelimiter/
│   │   ├── test_engine.py
│   │   ├── test_token_bucket.py
│   │   └── test_redis_store.py
│   ├── test_audit/
│   │   ├── test_engine.py
│   │   ├── test_jsonl_writer.py
│   │   └── test_hash_chain.py
│   ├── test_proxy/
│   │   ├── test_handler.py
│   │   ├── test_middleware.py
│   │   └── test_routing.py
│   └── test_config/
│       ├── test_loader.py
│       └── test_schema.py
├── integration/             # Requires Redis, filesystem
│   ├── conftest.py
│   ├── test_rate_limiter_redis.py
│   ├── test_audit_jsonl.py
│   ├── test_audit_redis_stream.py
│   ├── test_full_pipeline.py
│   └── test_config_hot_reload.py
└── e2e/                     # Full stack, Docker
    ├── conftest.py
    ├── test_proxy_openai_compat.py
    ├── test_proxy_anthropic_compat.py
    ├── test_dashboard.py
    ├── test_health_checks.py
    └── test_streaming_responses.py
```

### 12.2 Unit Tests

#### 12.2.1 Scrubber Tests

```python
# tests/unit/test_scrubber/test_regex.py
import pytest
from dataguard.scrubber.regex import RegexScrubber

class TestRegexScrubber:
    @pytest.fixture
    def scrubber(self):
        return RegexScrubber.from_config(default_config)
    
    @pytest.mark.asyncio
    async def test_scrub_ssn(self, scrubber):
        result = await scrubber.detect_and_redact("My SSN is 123-45-6789")
        assert "[REDACTED_SSN]" in result.text
        assert result.count == 1
    
    @pytest.mark.asyncio
    async def test_scrub_email(self, scrubber):
        result = await scrubber.detect_and_redact("Contact user@example.com")
        assert "[REDACTED_EMAIL]" in result.text
        assert result.count == 1
    
    @pytest.mark.asyncio
    async def test_scrub_multiple_pii(self, scrubber):
        text = "SSN: 123-45-6789, Email: user@example.com, Phone: 555-123-4567"
        result = await scrubber.detect_and_redact(text)
        assert result.count == 3
    
    @pytest.mark.asyncio
    async def test_no_pii_returns_unchanged(self, scrubber):
        text = "Hello, this is a normal message with no PII."
        result = await scrubber.detect_and_redact(text)
        assert result.text == text
        assert result.count == 0
    
    @pytest.mark.asyncio
    async def test_api_key_scrubbing(self, scrubber):
        result = await scrubber.detect_and_redact("key: sk-abc123def456ghi789jkl012mno")
        assert "[REDACTED_API_KEY]" in result.text
```

#### 12.2.2 Encryptor Tests

```python
# tests/unit/test_encryptor/test_aes_gcm.py
import pytest
from dataguard.encryptor.aes_gcm import AESGCMProvider

class TestAESGCMProvider:
    @pytest.fixture
    def provider(self):
        key = AESGCMProvider.generate_key()
        return AESGCMProvider(key)
    
    @pytest.mark.asyncio
    async def test_encrypt_decrypt_roundtrip(self, provider):
        plaintext = "sensitive data"
        ciphertext = await provider.encrypt(plaintext)
        decrypted = await provider.decrypt(ciphertext)
        assert decrypted == plaintext
    
    @pytest.mark.asyncio
    async def test_encrypted_differs_from_plaintext(self, provider):
        plaintext = "sensitive data"
        ciphertext = await provider.encrypt(plaintext)
        assert ciphertext != plaintext
    
    @pytest.mark.asyncio
    async def test_aad_authentication(self, provider):
        plaintext = "data"
        aad = b"associated-data"
        ct = await provider.encrypt(plaintext, aad=aad)
        # Correct AAD decrypts
        assert await provider.decrypt(ct, aad=aad) == plaintext
        # Wrong AAD fails
        with pytest.raises(InvalidTag):
            await provider.decrypt(ct, aad=b"wrong-aad")
```

#### 12.2.3 Classifier Tests

```python
# tests/unit/test_classifier/test_rule_based.py
import pytest
from dataguard.classifier.rule_based import RuleBasedClassifier
from dataguard.classifier.engine import SensitivityLevel

class TestRuleBasedClassifier:
    @pytest.mark.asyncio
    async def test_classify_ssn_as_confidential(self, classifier):
        body = {"messages": [{"content": "SSN: 123-45-6789"}]}
        level = await classifier.classify(body)
        assert level == SensitivityLevel.CONFIDENTIAL
    
    @pytest.mark.asyncio
    async def test_classify_health_as_restricted(self, classifier):
        body = {"messages": [{"content": "Patient diagnosis: diabetes"}]}
        level = await classifier.classify(body)
        assert level == SensitivityLevel.RESTRICTED
    
    @pytest.mark.asyncio
    async def test_classify_normal_as_public(self, classifier):
        body = {"messages": [{"content": "What is the weather today?"}]}
        level = await classifier.classify(body)
        assert level == SensitivityLevel.PUBLIC
    
    @pytest.mark.asyncio
    async def test_classify_secret_marker_rejects(self, classifier):
        body = {"messages": [{"content": "[NEVER_SEND] classified info"}]}
        level = await classifier.classify(body)
        assert level == SensitivityLevel.SECRET
```

### 12.3 Integration Tests

```python
# tests/integration/test_full_pipeline.py
import pytest
from httpx import AsyncClient, ASGITransport
from dataguard.main import create_app

@pytest.fixture
async def client():
    app = create_app("config/test.yaml")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c

class TestFullPipeline:
    @pytest.mark.asyncio
    async def test_pii_scrubbed_in_chat_request(self, client):
        response = await client.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-4",
                "messages": [
                    {"role": "user", "content": "My email is user@example.com"}
                ],
            },
            headers={"X-API-Key": "test-key"},
        )
        assert response.status_code == 200
        # Verify scrubbing was applied
        assert response.headers["X-DG-Scrub-Count"] == "1"
        assert response.headers["X-DG-Sensitivity"] == "CONFIDENTIAL"
    
    @pytest.mark.asyncio
    async def test_secret_level_request_rejected(self, client):
        response = await client.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-4",
                "messages": [
                    {"role": "user", "content": "[NEVER_SEND] top secret data"}
                ],
            },
            headers={"X-API-Key": "test-key"},
        )
        assert response.status_code == 403
    
    @pytest.mark.asyncio
    async def test_rate_limit_enforced(self, client):
        # Send requests beyond limit
        responses = []
        for _ in range(60):
            r = await client.post(
                "/v1/chat/completions",
                json={"model": "gpt-4", "messages": [{"role": "user", "content": "hi"}]},
                headers={"X-API-Key": "test-key", "X-DG-Tenant": "limited"},
            )
            responses.append(r)
        
        # At least one should be rate limited
        assert any(r.status_code == 429 for r in responses)
```

### 12.4 End-to-End Tests

```python
# tests/e2e/test_proxy_openai_compat.py
import pytest
import httpx

BASE_URL = "http://localhost:8000"

class TestOpenAICompatibility:
    @pytest.mark.asyncio
    async def test_chat_completions_endpoint(self):
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{BASE_URL}/v1/chat/completions",
                json={
                    "model": "gpt-4",
                    "messages": [{"role": "user", "content": "Hello!"}],
                    "max_tokens": 10,
                },
                headers={"Authorization": "Bearer test-key"},
                timeout=30,
            )
            assert response.status_code == 200
            data = response.json()
            assert "choices" in data
    
    @pytest.mark.asyncio
    async def test_pii_scrubbed_and_forwarded(self):
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{BASE_URL}/v1/chat/completions",
                json={
                    "model": "gpt-4",
                    "messages": [{"role": "user", "content": "Email: john@test.com"}],
                },
                headers={"Authorization": "Bearer test-key"},
                timeout=30,
            )
            assert response.status_code == 200
            assert int(response.headers.get("X-DG-Scrub-Count", 0)) >= 1
```

### 12.5 Test Configuration

```toml
# pyproject.toml [tool.pytest.ini_options]
[tool.pytest.ini_options]
testpaths = ["tests"]
asyncio_mode = "auto"
markers = [
    "slow: marks tests as slow (deselect with '-m \"not slow\"')",
    "integration: marks integration tests",
    "e2e: marks end-to-end tests",
    "benchmark: marks benchmark tests",
]
addopts = [
    "--strict-markers",
    "--tb=short",
    "-ra",
]
filterwarnings = [
    "error",
    "ignore::DeprecationWarning:httpx",
]
```

### 12.6 Coverage Targets

| Component | Line Coverage | Branch Coverage |
|-----------|--------------|-----------------|
| Scrubber | ≥ 95% | ≥ 90% |
| Encryptor | ≥ 95% | ≥ 90% |
| Classifier | ≥ 95% | ≥ 90% |
| Rate Limiter | ≥ 90% | ≥ 85% |
| Audit | ≥ 90% | ≥ 85% |
| Proxy Core | ≥ 85% | ≥ 80% |
| Config | ≥ 90% | ≥ 85% |
| **Overall** | **≥ 90%** | **≥ 85%** |

---

## 13. Roadmap to v1.0

### 13.1 Milestone Overview

```
v0.1.0 ──── v0.2.0 ──── v0.3.0 ──── v0.4.0 ──── v0.5.0 ──── v0.6.0 ──── v0.7.0 ──── v0.8.0 ──── v0.9.0 ──── v1.0.0
  │           │           │           │           │           │           │           │           │           │
  │           │           │           │           │           │           │           │           │           │
 Core      Dashboard   Streaming   OpenAI      Anthropic   Plugin      K8s         SSO/        Formal     Stable
 Proxy     & API       Support     Compat     Compat      System     Helm        RBAC        Audit      1.0
```

### 13.2 Detailed Milestones

#### v0.1.0 — Core Proxy (Week 1-4)

- [x] FastAPI proxy server with ASGI middleware chain
- [x] Basic request forwarding to upstream providers
- [x] API key authentication
- [x] Regex-based PII scrubber
- [x] Rule-based classifier
- [x] In-memory rate limiter (token bucket)
- [x] JSONL audit logger
- [x] YAML configuration with Pydantic validation
- [x] Docker + docker-compose setup
- [x] Basic unit tests (>80% coverage)

**Deliverable**: Working proxy that can scrub PII and forward requests.

#### v0.2.0 — Dashboard & Management API (Week 5-6)

- [ ] FastAPI management API endpoints
- [ ] Vue.js 3 dashboard SPA (scaffold)
- [ ] Health & readiness endpoints
- [ ] Configuration hot-reload
- [ ] Scrubber test endpoint
- [ ] Audit event querying
- [ ] SSE for real-time dashboard updates
- [ ] Prometheus metrics endpoint
- [ ] Integration test suite

**Deliverable**: Observable, manageable proxy with dashboard.

#### v0.3.0 — Streaming Support (Week 7-8)

- [ ] SSE streaming for OpenAI chat completions
- [ ] Chunked transfer encoding support
- [ ] Per-chunk PII detection (bounded window)
- [ ] Backpressure handling
- [ ] Stream timeout and cancellation
- [ ] Memory-bounded streaming buffers
- [ ] Streaming audit events

**Deliverable**: Full streaming proxy support.

#### v0.4.0 — OpenAI Full Compatibility (Week 9-10)

- [ ] All OpenAI API endpoints (completions, embeddings, images, audio, files)
- [ ] Function calling / tool use passthrough
- [ ] Fine-tuning API passthrough
- [ ] Batch API support
- [ ] Request/response schema validation
- [ ] Token counting and cost estimation
- [ ] OpenAI SDK compatibility testing

**Deliverable**: Drop-in OpenAI API replacement.

#### v0.5.0 — Anthropic Compatibility (Week 11-12)

- [ ] Anthropic Messages API support
- [ ] Tool use / function calling for Anthropic
- [ ] Vision (image) input handling
- [ ] Extended thinking / caching passthrough
- [ ] Anthropic SDK compatibility testing

**Deliverable**: Multi-provider proxy (OpenAI + Anthropic).

#### v0.6.0 — Plugin System (Week 13-15)

- [ ] Plugin registry with entry points
- [ ] Custom scrubber plugin API
- [ ] Custom classifier plugin API
- [ ] Custom encryptor plugin API
- [ ] Middleware plugin hooks (pre/post processing)
- [ ] Plugin configuration schema
- [ ] Plugin sandboxing (resource limits)
- [ ] Community plugin repository (docs only)

**Deliverable**: Extensible proxy with plugin architecture.

#### v0.7.0 — Kubernetes & Helm (Week 16-17)

- [ ] Helm chart for Kubernetes deployment
- [ ] Horizontal Pod Autoscaler configuration
- [ ] PodDisruptionBudget
- [ ] NetworkPolicy manifests
- [ ] ServiceMonitor for Prometheus Operator
- [ ] Grafana dashboard JSON export
- [ ] Vertical Pod Autoscaler recommendations
- [ ] K8s secrets integration

**Deliverable**: Production-ready Kubernetes deployment.

#### v0.8.0 — SSO & RBAC (Week 18-19)

- [ ] OIDC / OAuth2 single sign-on
- [ ] Role-based access control (admin, operator, viewer)
- [ ] Per-tenant permission enforcement
- [ ] Audit log access control
- [ ] Dashboard authentication
- [ ] Session management
- [ ] Multi-tenancy isolation guarantees

**Deliverable**: Enterprise-grade authentication and authorization.

#### v0.9.0 — Formal Audit & Compliance (Week 20-22)

- [ ] SOC 2 Type II control mapping
- [ ] HIPAA compliance documentation
- [ ] GDPR data processing documentation
- [ ] Audit log hash chain verification CLI
- [ ] Compliance report generation
- [ ] Data retention policy enforcement
- [ ] Right-to-erasure implementation (GDPR Art. 17)
- [ ] Data processing agreement template
- [ ] Penetration test results documentation

**Deliverable**: Compliance-ready proxy with audit guarantees.

#### v1.0.0 — Stable Release (Week 23-24)

- [ ] API stability guarantee (SemVer)
- [ ] Breaking change review of all public APIs
- [ ] Performance regression test suite
- [ ] Full documentation (API reference, tutorials, migration guide)
- [ ] Migration guide from v0.x to v1.0
- [ ] Deprecation warnings for any changed APIs
- [ ] Final security audit
- [ ] Long-term support (LTS) commitment (18 months)
- [ ] Release blog post and announcement

**Deliverable**: Production-stable, documented, supported v1.0.

### 13.3 Non-Goal / Future Beyond v1.0

These features are explicitly out of scope for v1.0 but may appear in v2.0:

- **On-device proxy** — Lightweight wasm-based proxy for edge/mobile
- **Federated scrubbing** — Cross-organization PII policies
- **Fine-tuned PII models** — Custom-trained NER models for domain-specific PII
- **GraphQL API** — Alternative query interface for management
- **Multi-region failover** — Automatic failover between cloud regions
- **Cost optimization** — Intelligent request routing to cheapest upstream
- **Prompt injection detection** — Detect and mitigate prompt injection attacks
- **Differential privacy** — Add calibrated noise for privacy guarantees

---

## Appendix A — Glossary

| Term | Definition |
|------|-----------|
| **AEAD** | Authenticated Encryption with Associated Data (e.g., AES-256-GCM) |
| **ASGI** | Asynchronous Server Gateway Interface — Python async web standard |
| **Fernet** | Symmetric encryption format from the `cryptography` library |
| **JSONL** | JSON Lines — one JSON object per line, newline-delimited |
| **JWKS** | JSON Web Key Set — set of public keys for JWT verification |
| **mTLS** | Mutual TLS — both client and server present certificates |
| **NER** | Named Entity Recognition — NLP technique for detecting entity types |
| **PGP** | Pretty Good Privacy — public-key encryption standard |
| **PII** | Personally Identifiable Information (SSN, email, phone, etc.) |
| **Presidio** | Microsoft's open-source PII detection and anonymization library |
| **RBAC** | Role-Based Access Control |
| **SSE** | Server-Sent Events — server-push over HTTP |
| **STRIDE** | Microsoft threat modeling framework (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) |
| **Token Bucket** | Rate limiting algorithm allowing burst traffic up to capacity |
| **uvloop** | High-performance event loop replacement for asyncio (libuv-based) |
| **WORM** | Write Once Read Many — immutable storage for audit logs |

---

## Appendix B — References

1. **Microsoft Presidio** — https://microsoft.github.io/presidio/
2. **FastAPI Documentation** — https://fastapi.tiangolo.com/
3. **Pydantic v2** — https://docs.pydantic.dev/
4. **OWASP API Security Top 10** — https://owasp.org/www-project-api-security/
5. **NIST SP 800-188 (De-Identification)** — https://csrc.nist.gov/publications/detail/sp/800-188/final
6. **GDPR Full Text** — https://gdpr-info.eu/
7. **HIPAA Security Rule** — https://www.hhs.gov/hipaa/for-professionals/security/index.html
8. **Cryptography (Python)** — https://cryptography.io/
9. **Token Bucket Algorithm** — https://en.wikipedia.org/wiki/Token_bucket
10. **STRIDE Threat Modeling** — https://learn.microsoft.com/en-us/azure/security/develop/threat-model
11. **OpenAI API Reference** — https://platform.openai.com/docs/api-reference
12. **Anthropic API Reference** — https://docs.anthropic.com/claude/reference
13. **GitHub Actions** — https://docs.github.com/en/actions
14. **Docker Compose** — https://docs.docker.com/compose/
15. **Prometheus** — https://prometheus.io/docs/
16. **spaCy NER** — https://spacy.io/api/annotation#named-entities
17. **Redis Streams** — https://redis.io/docs/data-types/streams/
18. **AES-256-GCM (NIST SP 800-38D)** — https://csrc.nist.gov/publications/detail/sp/800-38d/final

---

*Document generated on 2026-06-29. For the latest version, see the repository at
https://github.com/dataguard-fortress/dataguard-fortress*
