# 🏗️ Architecture Guide

Understanding how DataGuard Fortress works under the hood.

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Your Application                             │
│                    (Agent / API Client / LLM App)                   │
└────────────────────────────┬────────────────────────────────────────┘
                             │
                    HTTPS_PROXY or HTTP_PROXY
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    DataGuard Fortress Proxy                          │
│                   (localhost:8080 by default)                        │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │  1. Request Interception                                       │ │
│  │     - Parse HTTP/HTTPS request                                │ │
│  │     - Extract tenant_id from headers or body                  │ │
│  └────────────────────────────────────────────────────────────────┘ │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │  2. Tenant Resolution                                          │ │
│  │     - Load tenant config from tenants/*.yaml                  │ │
│  │     - Hot-reload on file change                               │ │
│  │     - Apply per-tenant policies                               │ │
│  └────────────────────────────────────────────────────────────────┘ │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │  3. PII Classification & Scrubbing                             │ │
│  │     - Analyze payload for 52 PII patterns                     │ │
│  │     - Classify as PUBLIC/INTERNAL/CONFIDENTIAL/RESTRICTED    │ │
│  │     - Scrub matched patterns (regex replacement)              │ │
│  │     - Log what was found & redacted                           │ │
│  └────────────────────────────────────────────────────────────────┘ │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │  4. Rate Limiting (Per Tenant)                                 │ │
│  │     - Token bucket algorithm                                  │ │
│  │     - Sliding window counter                                  │ │
│  │     - Hard cap (per_minute)                                   │ │
│  │     - Redis or in-memory backend                              │ │
│  └────────────────────────────────────────────────────────────────┘ │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │  5. Optional Encryption at Rest                                │ │
│  │     - AES-GCM 256-bit encryption                              │ │
│  │     - Encrypts audit logs & cached data                       │ │
│  │     - Key rotation support                                    │ │
│  └────────────────────────────────────────────────────────────────┘ │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │  6. Audit Logging (Append-Only)                                │ │
│  │     - JSONL format (one JSON per line)                        │ │
│  │     - SHA-256 hash chain integrity                            │ │
│  │     - Tamper detection via hash verification                  │ │
│  │     - Configurable retention & rotation                       │ │
│  └────────────────────────────────────────────────────────────────┘ │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │  7. Request Forwarding                                         │ │
│  │     - Forward scrubbed payload to upstream                    │ │
│  │     - Forward response back to client                         │ │
│  │     - Inject DataGuard headers for traceability               │ │
│  └────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
                             │
                             ▼
        ┌────────────────────────────────────────┐
        │    Third-Party LLM Provider            │
        │   (OpenAI, Anthropic, Google, etc.)   │
        └────────────────────────────────────────┘
```

---

## Data Flow Example

### Scenario: User queries Claude through DataGuard

```json
{
  "step": 1,
  "event": "Request arrives at DataGuard",
  "payload": {
    "user_message": "My email is john.doe@acme.com and SSN is 123-45-6789"
  }
}
```

↓

```json
{
  "step": 2,
  "event": "Tenant resolution",
  "tenant": "acme-corp",
  "policy": {
    "rate_limit": 20,
    "scrubber_enabled": true,
    "min_confidence": 0.85
  }
}
```

↓

```json
{
  "step": 3,
  "event": "PII detection & scrubbing",
  "detections": [
    { "type": "email", "pattern": "john.doe@acme.com", "confidence": 0.99 },
    { "type": "ssn", "pattern": "123-45-6789", "confidence": 0.98 }
  ],
  "scrubbed_payload": {
    "user_message": "My email is [REDACTED_EMAIL] and SSN is [REDACTED_SSN]"
  }
}
```

↓

```json
{
  "step": 4,
  "event": "Rate limit check",
  "tenant": "acme-corp",
  "current_rate": 15.2,
  "limit": 20.0,
  "action": "ALLOW"
}
```

↓

```json
{
  "step": 5,
  "event": "Audit log entry (append-only)",
  "timestamp": "2026-07-07T10:30:45Z",
  "tenant": "acme-corp",
  "pii_detected": 2,
  "request_hash": "sha256:abc123...",
  "prev_hash": "sha256:def456...",
  "action": "SCRUB_AND_FORWARD"
}
```

↓

```json
{
  "step": 6,
  "event": "Request forwarded to LLM",
  "headers": {
    "X-DataGuard-Tenant": "acme-corp",
    "X-DataGuard-Audit-Id": "evt_7f8a9b0c"
  },
  "payload": {
    "user_message": "My email is [REDACTED_EMAIL] and SSN is [REDACTED_SSN]"
  }
}
```

---

## Component Deep Dive

### 1. Request Handler (`src/proxy/handler.py`)

- **Responsibility**: Intercept HTTP/HTTPS requests
- **Technology**: FastAPI + Uvicorn
- **Key method**: `handle_request(request: Request) -> Response`

```python
async def handle_request(request: Request):
    # Parse incoming request
    tenant_id = extract_tenant_id(request)
    payload = await request.body()
    
    # Route through pipeline
    scrubbed = await scrubber.scrub(payload, tenant_id)
    rate_limited = await rate_limiter.check(tenant_id, len(scrubbed))
    
    if rate_limited:
        return Response(status_code=429)
    
    # Audit log
    await audit_logger.log(tenant_id, scrubbed, "FORWARD")
    
    # Forward to upstream
    return await forward_to_upstream(scrubbed)
```

### 2. Scrubber Engine (`src/scrubber/engine.py`)

- **Responsibility**: PII detection & redaction
- **Technology**: Pre-compiled regex patterns
- **Key features**:
  - 52 built-in presets (email, SSN, credit cards, API keys, etc.)
  - Confidence scoring (0.0 to 1.0)
  - Sensitivity classification
  - Configurable custom patterns per tenant

### 3. Rate Limiter (`src/ratelimiter/engine.py`)

- **Responsibility**: Per-tenant rate limiting
- **Algorithms**:
  - Token bucket (smooth bursts)
  - Sliding window (prevent spike abuse)
- **Backends**: Redis (distributed) or in-memory

### 4. Audit Logger (`src/audit/logger.py`)

- **Responsibility**: Immutable audit trail
- **Format**: JSONL (one JSON per line)
- **Integrity**: SHA-256 hash chain
- **Features**: Tamper detection, encryption (optional)

### 5. Tenant Manager (`src/tenants/manager.py`)

- **Responsibility**: Load & manage per-tenant configs
- **Format**: YAML (human-friendly)
- **Feature**: Hot-reload on file change (no restart)

### 6. Dashboard (`src/dashboard/app.py`)

- **Responsibility**: Real-time monitoring & testing
- **Technology**: Server-Sent Events (SSE) + HTML5
- **Features**:
  - Live metrics (requests/sec, PII detected)
  - Scrub playground (test patterns)
  - Audit feed (real-time)
  - Presets browser

---

## Performance Characteristics

| Component | Latency | Throughput | Scaling |
|---|---|---|---|
| **Scrubber** | 5-15ms (52 patterns) | ~10k req/sec | Linear with pattern count |
| **Rate Limiter** | <1ms (in-memory) | >100k req/sec | Depends on backend (Redis ~10k/sec) |
| **Audit Logger** | 2-5ms (disk I/O) | ~5k writes/sec | Linear with disk speed |
| **Total E2E** | 10-25ms | ~5k req/sec | Bottleneck: disk I/O |

---

## Security Guarantees

| Guarantee | How It Works |
|---|---|
| **Fail-Closed** | If scrubbing fails, request is blocked (not leaked) |
| **No Telemetry** | Zero external API calls from proxy itself |
| **Audit Trail** | Append-only JSONL with SHA-256 hash chain |
| **Encryption** | Optional AES-GCM 256-bit at rest |
| **Rate Limiting** | Per-tenant token bucket + sliding window |
| **Tenant Isolation** | Separate configs, separate keys, no cross-tenant data |

---

<div align="center">

**Questions?** [Start a discussion](../../discussions) or file an [issue](../../issues).

</div>