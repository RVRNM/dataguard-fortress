#!/bin/bash
# DataGuard Fortress — FINAL VERIFICATION SCRIPT
set -euo pipefail
cd "$(dirname "$0")/.."

pass=0
fail=0

check() {
  if eval "$2" >/dev/null 2>&1; then
    echo "  [PASS] $1"
    pass=$((pass+1))
  else
    echo "  [FAIL] $1"
    fail=$((fail+1))
  fi
}

echo "=============================================="
echo "  DataGuard Fortress FINAL VERIFICATION"
echo "=============================================="

echo ""
echo "[1] Project structure"
check "pyproject.toml"           "test -f pyproject.toml"
check "Dockerfile"              "test -f Dockerfile"
check "docker-compose.yml"      "test -f docker-compose.yml"
check "README.md"               "test -f README.md"
check "SECURITY.md"             "test -f SECURITY.md"
check "SKILL.md"                "test -f SKILL.md || test -f ../.hermes/skills/security/dataguard-fortress/SKILL.md"
check "CHANGELOG.md"            "test -f CHANGELOG.md"
check "ARCHITECTURE.md"         "test -f docs/ARCHITECTURE.md"
check "src/main.py"             "test -f src/main.py"
check "src/proxy_server.py"     "test -f src/proxy_server.py"
check "src/scrubber.py"         "test -f src/scrubber.py"
check "src/classifier.py"       "test -f src/classifier.py"
check "src/orchestrator.py"     "test -f src/orchestrator.py"
check "src/token_bucket.py"     "test -f src/token_bucket.py"
check "src/sliding_window_ratelimiter.py" "test -f src/sliding_window_ratelimiter.py"
check "src/tenant.py"           "test -f src/tenant.py"
check "src/dashboard.py"        "test -f src/dashboard.py"
check "src/audit.py"            "test -f src/audit.py"
check "src/config.py"           "test -f src/config.py"
check "tests/test_scrubber.py"  "test -f tests/test_scrubber.py"
check "tests/test_v03.py"       "test -f tests/test_v03.py"
check "tests/test_proxy.py"     "test -f tests/test_proxy.py"
check "tests/audit_complet.py"  "test -f tests/audit_complet.py"

echo ""
echo "[2] PII Scrubbing (10 types)"
check "email"         'python -c "import asyncio;from src.scrubber import PIIScrubber;s=PIIScrubber(min_confidence=0.0);r=asyncio.run(s.scrub(\"a@b.co\"));assert \"a@b.co\" not in r.scrubbed_text'
check "ssn"          'python -c "import asyncio;from src.scrubber import PIIScrubber;s=PIIScrubber(min_confidence=0.0);r=asyncio.run(s.scrub(\"1236789\"));assert \"123-45-6789\" not in r.scrubbed_text'
a"      'python -c "import asyncio;from src.scrubber import PIIScrubber;s=PIIScrubber(min_confidence=0.0);r=asyncio.run(s.scrub(\"4111-1111-111-1111\"));assert \"1111\" not in r.scrubbed_text'
check "openai_key"   'python -c "import asyncio;from src.scrubber import PIIScrubber;s=PIIScrubber(min_confidence=0.0);r=asyncio.run(s.scrub(\"sk-abcdefghijklmnopqrstuvwxyz1234567890\"));assert \"sk-abc\" not in r.scrubbed_text'
check "btc"          'python -c "import asyncio;from src.scrubber import PIIScrubber;s=PIIScrubber(min_confidence=0.0);r=asyncio.run(s.scrub(\"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\"));assert \"1A1z\" not in r.scrubbed_text'
check "eth"          'python -c "import asyncio;from src.scrubber import PIIScrubber;s=PIIScrubber(min_confidence=0.0);r=asyncio.run(s.scrub(\"0x742d35Cc6634C0532925a3b844Bc9e7595f2bD28\"));assert \"0x74\" not in r.scrubbed_text'
check "ipv4"         'python -c "import asyncio;from src.scrubber import PIIScrubber;s=PIIScrubber(min_confidence=0.0);r=asyncio.run(s.scrub(\"192.168.1.100\"));assert \"192.168\" not in r.scrubbed_text'
check "ipv6"         'python -c "import asyncio;from src.scrubber import PIIScrubber;s=PIIScrubber(min_confidence=0.0);r=asyncio.run(s.scrub(\"2001:0db8:85a3::7334\"));assert \"2001:db8\" not in r.scrubbed_text'
check "ssn_pi"       'python -c "import asyncio;from src.scrubber import PIIScrubber;s=PIIScrubber0.2);r=asyncio.run(s.scrub(\"my secret is abc\"));assert r.scrubbed_count == 0'

echo ""
echo "[3] Classification (4 levels)"
check "PUBLIC"        'python -c "import asyncio;from src.classifier import DataClassifier, SensitivityLevel;c=DataClassifier();r=asyncio.run(c.classify(\"Hello world\"));assert r.level==SensitivityLevel.PUBLIC'
check "INTERNAL"      'python -c "import asyncio;from src.classifier import DataClassifier, SensitivityLevel;c=DataClassifier();r=asyncio.run(c.classify(\"Internal memo: salary\"));assert r.level==SensitivityLevel.INTERNAL'
check "CONFIDENTIAL"  'python -c "import asyncio;from src.classifier import DataClassifier, SensitivityLevel;c=DataClassifier();r=asyncio.run(c.classify(\"The password is secret123\"));assert r.level==SensitivityLevel.CONFIDENTIAL'
check "RESTRICTED"    'python -c "import asyncio;from src.classifier import DataClassifier, SensitivityLevel;c=DataClassifier();r=asyncio.run(c.classify(\"SSN: 123-45-6789 CC: 4111-1111-1111-1111\"));assert r.level==SensitivityLevel.RESTRICTED'

echo ""
echo "[4] Audit logger"
check "Audit writes JSONL" 'python -c "import asyncio;import os;from pathlib import Path;from src.audit import AuditLogger,AuditEvent,AuditEventType;"
os.makedirs("./tmp_test", exist_ok=True)
a = AuditLogger(); a._log_dir = Path("./tmp_test"); asyncio.run(a.log(AuditEvent(event_type=EventType.REQUEST, upstream="o.com"))); asyncio.run(a.aclose())
assert=="./tmp_test/audit.jsonl"); os.remove("./tmp_test/audit.jsonl"); os.rmdir("./tmp_test")'

echo ""
echo "[5] Tests unitaires"
check "137 pytest pass" "python -m pytest tests/test_scrubber.py tests/test_v03.py tests/test_proxy.py -q --tb=no 2>&1 | grep -q '137 passed'"

echo ""
echo "=============================================="
echo "  RESULT: $pass passed, $fail failed"
echo "=============================================="
[ "$fail" -eq 0 ] && echo "ALL CHECKS PASSED" || echo "SOME CHECKS FAILED"
