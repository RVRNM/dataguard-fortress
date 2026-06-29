# DataGuard Fortress — Media Kit

Assets for README, social posts, and launch materials.

## 1. Badges (for README)

```md
![Python](https://img.shields.io/badge/python-3.11+-blue.svg)
![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)
![Tests](https://img.shields.io/badge/tests-16%20PII%20demo-brightgreen)
![Security](https://img.shields.io/badge/security-0%20HIGH-red.svg)
![Docker](https://img.shields.io/badge/docker-ready-blue)
![PII Presets](https://img.shields.io/badge/52%20PII%20presets-orange)
```

## 2. SVG Logo Banner

Save as `assets/banner.svg` (or use shields.io):

```svg
<svg xmlns="http://www.w3.org/2000/svg" width="800" height="200">
  <rect width="800" height="200" rx="12" fill="#0f172a"/>
  <text x="400" y="80" font-family="monospace" font-size="36" fill="#3b82f6" text-anchor="middle">DataGuard Fortress</text>
  <text x="400" y="120" font-family="monospace" font-size="18" fill="#94a3b8" text-anchor="middle">Privacy Proxy for AI Agents — PII Scrub + Classify + Audit</text>
  <text x="400" y="160" font-family="monospace" font-size="14" fill="#10b981" text-anchor="middle">52 PII presets · 4 sensitivity levels · Multi-tenant · Open-source</text>
</svg>
```

Generate with Python:
```python
# generate_banner.py
svg = '''<svg xmlns="http://www.w3.org/2000/svg" width="800" height="200">
  <rect width="800" height="200" rx="12" fill="#0f172a"/>
  <text x="400" y="80" font-family="monospace" font-size="36" fill="#3b82f6" text-anchor="middle">DataGuard Fortress</text>
  <text x="400" y="120" font-family="monospace" font-size="18" fill="#94a3b8" text-anchor="middle">Privacy Proxy for AI Agents — PII Scrub + Classify + Audit</text>
</svg>'''
Path("assets/banner.svg").write_text(svg)
```

## 3. Terminal Demo (text-only version, zero deps)

Since Docker/asciinema are unavailable locally's a MANUAL demo script
that anyone can run. Save as `demo/demo.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

echo "═══════════════════════════════════════════════════════"
echo " ️ DataGuard Fortress v0.4 — Quick Demo"
echo "═══════════════════════════════════════════════════════"

echo ""
echo "[1/4] Install"
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[prod]" -q

echo ""
echo "[2/4] Generate config"
dataguard --generate-config config.yaml

echo ""
echo "[3/4] Start proxy (background)"
dataguard --port 18080 &
PROXY_PID=$!
sleep 2

echo ""
echo "[4/4] Demo: PII scrubbing via proxy"
echo "  Test email:"
echo "  Email me at john.d@example.com please" | python3 -c "
import sys
text = sys.stdin.read().strip()
from src.scrubber import PIIScrubber
import asyncio
s = PIIScrubber(min_confidence=0.0)
r = asyncio.run(s.scrub(text))
print(f'  → {r.scrubbed_text}')
"
echo ""
echo "  Test SSN:"
echo "  My SSN is 123-45-6789" | python3 -c "
import sys
text = sys.stdin.read().strip()
from src.scrubber import PIIScrubber
import asyncio
s = PIIIScrubber(min_confidence=0.0)
r = asyncio.run(s.scrub(text))
print(f'  → {r.scrubbed_text}')
"
echo ""
echo "  Test multiple PII:"
echo "  Contact: alice@corp.com, CC: 4111-1111-1111-1111, BTC: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" | python3 -c "
import sys
text = sys.stdin.read().strip()
from src.scrubber import PIIScrubber
import asyncio
s = PIIScrubber(min_confidence=0.0)
r = asyncio.run(s.scrub(text))
print(f'  → {r.scrubbed_text}')
"

echo ""
echo "--- Dashboard (text) ---"
curl -s http://127.0.0.1:18080/api/stats 2>/dev/null || echo "(dashboard running on http://127.0.0.1:18080/)"

echo ""
echo "[Cleanup]"
kill $PROXY_PID 2>/dev/null || true

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  Demo complete! Try:"
echo "  $ dataguard --port 8080"
echo "  $ export HTTP_PROXY=http://localhost:8080"
echo "  $ curl -x http://localhost:8080 http://httpbin.org/get"
echo "═══════════════════════════════════════════════════════"
```

## 4. TerminalScreenshots (HTML)

Save the actual dashboard HTML screenshot from the browser at `/screenshot.png`
(must be done after `dataguard --port 8080` then screenshot http://localhost:8080/)

## 5. asciinema record

If you have asciinema:
```bash
asciinema rec demo/demo.cast -c './demo/demo.sh'
# Convert to GIF if you have asciicast2gif:
asciicast2gif demo/demo.cast assets/demo.gif
```

## 6. Social Posts

### Twitter/X
```
 Meet DataGuard Fortress — the privacy proxy your AI agents need.

  52 PII presets scrub emails/SSN/CCs/API keys inline
  4-level sensitivity classification (PUBLIC → RESTRICTED)
  Per-tenant rate limiting + audit logging
  Self-hosted, 0 external calls, Apache-2.0

 github.com/ANON/dataguard-fortress
```

### Reddit (r/selfhosted, r)`
```
[Project] DataGuard Fortress — Self-hosted privacy proxy for AI agents

TL;DR: A Python async proxy that scrubs PII before API calls reach OpenAI/Anthropic.
52 PII presets, 4-level classification, token+sliding rate limiting, JSONL audit.

github.com/ANON/dataguard-fortress
```

### Hacker News Show HN
```
Show HN: DataGuard Fortress — Self-hosted privacy proxy for AI agents

- 52 PII regex presets for emails, SSNs, credit cards, API keys, crypto addresses, medical records
- Sensitivity classifier: PUBLIC → INTERNAL → CONFIDENTIAL → RESTRICTED
- Per-tenant YAML configs with hot-reload
- Token bucket + sliding window rate limiters
- JSONL audit log with hash chain integrity
- FastAPI dashboard with SSE
- 137 tests, 0 HIGH vulns, 0 secrets in code

Apache-2.0. Self-hosted, no telemetry.
github.com/ANON/dataguard-fortress
```
