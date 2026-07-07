# 🚀 Quick Start Guide - DataGuard Fortress

Get up and running with DataGuard Fortress in 5 minutes.

## Prerequisites

- Python 3.11+
- Docker & Docker Compose (optional)
- Basic familiarity with environment variables

## Option 1: Local Installation (Fastest)

```bash
# 1. Clone the repository
git clone https://github.com/RVRNM/dataguard-fortress.git
cd dataguard-fortress

# 2. Install with development dependencies
pip install -e ".[dev]"

# 3. Copy and customize configuration
cp .env.example .env

# 4. Start the proxy
dataguard --port 8080

# 5. Verify it's running
curl http://localhost:8080/health
```

✅ Your proxy is now running on `http://localhost:8080`

---

## Option 2: Docker (Recommended for Production)

```bash
# 1. Clone the repository
git clone https://github.com/RVRNM/dataguard-fortress.git
cd dataguard-fortress

# 2. Build and run with Docker Compose
docker-compose up -d --build

# 3. Check logs
docker-compose logs -f dataguard-fortress

# 4. Verify it's running
curl http://localhost:8080/health
```

✅ Your proxy is now running in Docker

---

## Option 3: AI Agent Skill (For Claude, Cursor, etc.)

```bash
# Install as a skill for your AI agent
node skills/dataguard-fortress/install.js --agent claude

# Or for multiple agents
node skills/dataguard-fortress/install.js --agent all
```

**Supported agents:** Claude Code, OpenAI Codex CLI, Cursor, Aider, Cline, Continue, OpenCode, Hermes Agent.

---

## 🎯 Common Use Cases

### Use Case 1: Protect OpenAI API Calls

```python
import os
import openai

# Point OpenAI client through DataGuard proxy
openai.api_base = "http://localhost:8080"
openai.api_key = os.getenv("OPENAI_API_KEY")

# This request will have PII automatically scrubbed
response = openai.ChatCompletion.create(
    model="gpt-4",
    messages=[
        {
            "role": "user",
            "content": "User email: john.doe@acme.com, SSN: 123-45-6789"
        }
    ]
)
# Output: PII is automatically scrubbed before sending
```

### Use Case 2: Rate-Limit Per Tenant

Create tenant configs in `tenants/` directory:

```yaml
# tenants/acme-corp.yaml
tenant_id: acme-corp
name: Acme Corporation
rate_limit:
  rate: 20.0           # 20 requests/second
  capacity: 100        # burst up to 100
  per_minute: 1200     # hard cap of 1200/min
scrubber:
  enabled: true
  fail_closed: true
```

Restart or rely on hot-reload (if enabled). Tenant policies apply automatically.

### Use Case 3: Monitor PII in Real-Time

```bash
# 1. Access the dashboard
open http://localhost:8080

# 2. View real-time metrics
#    - Requests/sec
#    - PII detected
#    - Blocked requests
#    - Audit feed (live)

# 3. Test scrubbing in the Scrub Playground
```

### Use Case 4: Compliance & Audit Logs

```bash
# Audit logs are stored in JSONL format (append-only)
cat logs/audit.jsonl

# Each entry includes:
# - timestamp
# - tenant_id
# - request_hash (SHA-256)
# - PII detected
# - action taken
# - response code
```

---

## 🔧 Configuration Essentials

### Minimal Configuration

Create `config.yaml`:

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
  rate: 10.0          # 10 tokens/second
  capacity: 50        # burst capacity
  per_minute: 600     # hard cap

audit:
  enabled: true
  log_dir: ./logs
```

### Environment Variables

| Variable | Default | Use Case |
|---|---|---|
| `DG_ENCRYPTION_KEY` | — | Enable AES-GCM encryption at rest |
| `DG_REDIS_URL` | — | Use Redis for distributed rate limiting |
| `DG_LOG_LEVEL` | `INFO` | Set verbosity (DEBUG, INFO, WARNING, ERROR) |
| `DG_CONFIG_PATH` | `./config.yaml` | Custom config location |

---

## 📊 Dashboard Features

Visit `http://localhost:8080/` to access:

| Feature | What It Shows |
|---|---|
| **Live Metrics** | Requests/sec, errors, PII detected |
| **Scrub Playground** | Test PII detection on custom text |
| **Presets Browser** | Search 52 built-in PII patterns |
| **Audit Feed** | Real-time event stream (SSE) |

---

## 🐛 Troubleshooting

### Port Already in Use

```bash
# Use a different port
dataguard --port 9090

# Or kill the process on port 8080
lsof -ti:8080 | xargs kill -9
```

### PII Not Being Detected

1. Check confidence threshold in config:
   ```yaml
   scrubber:
     min_confidence: 0.5  # Lower = more sensitive
   ```

2. Verify presets are loaded:
   ```bash
   curl http://localhost:8080/api/presets | jq '.[] | .name'
   ```

### Rate Limit Not Working

1. Ensure Redis is running (if using distributed mode):
   ```bash
   redis-cli ping
   # Should return: PONG
   ```

2. Check tenant config has rate_limit section:
   ```bash
   cat tenants/*.yaml | grep -A 3 "rate_limit:"
   ```

---

## ✅ Next Steps

1. **Read the [Configuration Guide](./CONFIGURATION.md)** for advanced options
2. **Explore [Examples](./EXAMPLES.md)** for real-world integrations
3. **Check [Architecture](./ARCHITECTURE.md)** to understand how it works
4. **Review [Security Policy](../SECURITY.md)** before production use

---

## 💬 Getting Help

- 📖 **Documentation**: Check [README](../README.md)
- 🐛 **Found a bug?** [Open an issue](../../issues)
- 💡 **Feature request?** [Discuss here](../../discussions)
- 🔐 **Security concern?** Email security@dataguard-fortress.dev

---

<div align="center">

**🎉 Welcome to DataGuard Fortress!**

Have questions? [Start a discussion](../../discussions) or check our [FAQ](./FAQ.md).

</div>