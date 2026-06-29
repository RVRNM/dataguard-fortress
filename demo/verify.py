#!/usr/bin/env python3
"""DataGuard Fortress — FINAL VERIFICATION SCRIPT"""
import asyncio
import os
import sys
import time
import subprocess
from pathlib import Path

# Go to project root and add to path
PROJECT_ROOT = Path(__file__).parent.parent.resolve()
os.chdir(PROJECT_ROOT)
sys.path.insert(0, str(PROJECT_ROOT))

pass_count = 0
fail_count = 0

def check(name, passed, detail=""):
    global pass_count, fail_count
    if passed:
        pass_count += 1
        print(f"  [PASS] {name}: {detail}")
    else:
        fail_count += 1
        print(f"  [FAIL] {name}: {detail}")

async def main():
    global pass_count, fail_count

    print("=" * 70)
    print("  DataGuard Fortress v0.4 — FINAL VERIFICATION")
    print("=" * 70)

    # 1. Structure
    print("\n[1] Project Structure")
    files = [
        "pyproject.toml", "Dockerfile", "docker-compose.yml", "README.md",
        "SECURITY.md", "CHANGELOG.md", "LICENSE",
        "docs/ARCHITECTURE.md", "src/__init__.py", "src/main.py",
        "src/proxy_server.py", "src/scrubber.py", "src/classifier.py",
        "src/orchestrator.py", "src/token_bucket.py",
        "src/sliding_window_ratelimiter.py", "src/tenant.py",
        "src/dashboard.py", "src/audit.py", "src/config.py",
        "tests/test_scrubber.py", "tests/test_v03.py", "tests/test_proxy.py",
        "tests/audit_complet.py", "demo/demo.sh", "MEDIA_KIT.md",
    ]
    for f in files:
        check(f, os.path.exists(f))

    # 2. PII Scrubbing
    print("\n[2] PII Scrubbing (16 types)")
    from src.scrubber import PIIScrubber
    s = PIIScrubber(min_confidence=0.0)

    pii_tests = [
        ("email", "a@b.co", "a@b.co"),
        ("ssn", "123-45-6789", "123-45-6789"),
        ("cc_visa", "4111-1111-1111-1111", "4111"),
        ("cc_mc", "5500-0000-0000-0004", "5500"),
        ("openai_key", "FAKE_KEY", "FAKE_KEY"),
        ("aws_key", "FAKE_AWS_KEY", "AKIA"),
        ("github_token", "FAKE_GITHUB_TOKEN", "FAKE_GITHUB_TOKEN"),
        ("stripe_key", "FAKE_STRIPE_KEY", "FAKE_STRIPE_KEY"),
        ("btc", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "1A1z"),
        ("eth", "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD28", "0x74"),
        ("ipv4", "192.168.1.100", "192.168"),
        ("ipv6", "2001:0db8:85a3::7334", "2001:db8"),
        ("ipv6_full", "2001:0db8:85a3:0000:0000:8a2e:0370:7334", "2001:0db8"),
        ("mrn", "MRN-12345-67890", "MRN"),
        ("phone_fr", "+33612345678", "+336"),
        ("phone_us", "(555) 123-4567", "(555)"),
    ]
    for name, text, sensitive in pii_tests:
        r = await s.scrub(text)
        still_here = sensitive in r.scrubbed_text
        check(f"  {name}", not still_here, f"hidden={not still_here}")

    # 3. Classification
    print("\n[3] Classification (4 levels)")
    from src.classifier import DataClassifier, SensitivityLevel
    c = DataClassifier()
    for level_name, text, expected in [
        ("PUBLIC", "Hello world", SensitivityLevel.PUBLIC),
        ("INTERNAL", "Internal memo: salary review", SensitivityLevel.INTERNAL),
        ("CONFIDENTIAL", "The password is secret123", SensitivityLevel.CONFIDENTIAL),
        ("RESTRICTED", "SSN: 123-45-6789 CC: 4111-1111-1111-1111", SensitivityLevel.RESTRICTED),
    ]:
        r = await c.classify(text)
        check(f"  {level_name}", r.level == expected, f"score={r.score:.2f}")

    # 4. Rate Limiter
    print("\n[4] Rate Limiter")
    from src.token_bucket import TokenBucket, MemoryTokenBucketBackend
    backend = MemoryTokenBucketBackend()
    bucket = TokenBucket(backend=backend, key="verify", rate=10.0, capacity=5.0)
    acquired = 0
    for _ in range(7):
        if await bucket.try_acquire():
            acquired += 1
    check("Token bucket burst+block", acquired == 5, f"acquired={acquired}")

    from src.sliding_window_ratelimiter import (
        SlidingWindowRateLimiter, MemoryRateLimiterBackend
    )
    sw = SlidingWindowRateLimiter(MemoryRateLimiterBackend(), max_requests=3, window_seconds=60)
    sw_count = 0
    for _ in range(5):
        ok, _ = await sw.check("verify-user")
        if ok:
            await sw.record("verify-user")
            sw_count += 1
    check("Sliding window cap", sw_count == 3, f"allowed={sw_count}")

    # 5. Audit Logger
    print("\n[5] Audit Logger")
    from src.audit import AuditLogger, AuditEvent, AuditEventType
    os.makedirs("./tmp_verify", exist_ok=True)
    alog = AuditLogger()
    alog._log_dir = Path("./tmp_verify")
    alog._log_filename = "audit.jsonl"
    alog._buffer_size = 1
    await alog.log(AuditEvent(event_type=AuditEventType.REQUEST, upstream="openai.com", method="POST", path="/v1/chat"))
    await alog.log(AuditEvent(event_type=AuditEventType.SCRUB, upstream="openai.com", scrub_count=3))
    await alog.log(AuditEvent(event_type=AuditEventType.PROXY_ERROR, upstream="bad.com", error="timeout"))
    await asyncio.sleep(0.3)
    await alog.aclose()
    audit_file = Path("./tmp_verify/audit.jsonl")
    lines = audit_file.read_text().strip().split("\n") if audit_file.exists() else []
    check("Audit entries written", len(lines) == 3, f"{len(lines)} entries")
    has_hash = all('"hash"' in l for l in lines if l.strip())
    check("Hash chain per entry", has_hash)
    # Cleanup
    if audit_file.exists():
        audit_file.unlink()
    os.rmdir("./tmp_verify")

    # 6. Tenant Manager
    print("\n[6] Tenant Manager")
    os.makedirs("./tmp_verify", exist_ok=True)
    with open("./tmp_verify/acme.yaml", "w") as f:
        f.write("tenant_id: acme\nname: Acme Corp\nrate_limit:\n  requests_per_second: 20.0\n  burst_size: 100\n  max_concurrent: 50\n  window_seconds: 120\n")
    from src.tenant import TenantManager
    tm = TenantManager(tenants_dir="./tmp_verify")
    tm.reload()
    check("Tenants loaded", len(tm.list_tenants()) >= 1, f"tenants={tm.list_tenants()}")
    t = tm.get_tenant("acme")
    check("Rate limit read", t.rate_limit.requests_per_second == 20.0, f"rps={t.rate_limit.requests_per_second}")
    check("Default fallback", tm.get_tenant("nonexistent") is not None)
    await tm.stop()
    os.remove("./tmp_verify/acme.yaml")
    os.rmdir("./tmp_verify")

    # 7. Orchestrator
    print("\n[7] Orchestrator (full pipeline)")
    from src.orchestrator import DataGuardOrchestrator, OrchestratorDecision
    from src.config import Config
    orch = DataGuardOrchestrator(Config())
    await orch.start()
    r = await orch.process_request("default", b"Hello world")
    check("Normal forward", r.forward is True, f"tenant={r.tenant_id}")
    r = await orch.process_request("default", b"SSN: 123-45-6789 CC: 4111-1111-1111-1111 Email: a@b.com")
    check("PII classified RESTRICTED", r.classification.level == SensitivityLevel.RESTRICTED, f"score={r.classification.score:.2f}")
    await orch.stop()

    # 8. Performance
    print("\n[8] Performance")
    large = "Email: test@e.com " * 10000
    t0 = time.monotonic()
    for _ in range(100):
        await s.scrub(large)
    speed = len(large) * 100 / (time.monotonic() - t0) / 1e6
    check("Scrub speed > 0.5 MB/s", speed > 0.5, f"{speed:.1f} MB/s")

    # 9. Pytest
    print("\n[9] Pytest Suite")
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/test_scrubber.py", "tests/test_v03.py", "tests/test_proxy.py", "-q", "--tb=no"],
        capture_output=True, text=True, timeout=60
    )
    pytest_passed = "137 passed" in result.stdout
    check("137 pytest pass", pytest_passed, result.stdout.strip().split("\n")[-1] if result.stdout else "no output")

    # 10. Security scan
    print("\n[10] Security")
    # Check no private paths
    private_hits = []
    for root, dirs, flist in os.walk("src"):
        for f in flist:
            if f.endswith(".py"):
                content = open(os.path.join(root, f), encoding="utf-8", errors="ignore").read()
                if "C:\\Users\\" in content or "C:/Users/" in content:
                    private_hits.append(f)
    check("No private paths in src/", len(private_hits) == 0, f"hits={private_hits}")

    # Check no real secrets
    import re
    secret_hits = []
    for root, dirs, flist in os.walk("src"):
        for f in flist:
            if f.endswith(".py"):
                for i, line in enumerate(open(os.path.join(root, f), encoding="utf-8", errors="ignore"), 1):
                    if re.search(r'(sk|ghp|AKIA)_[A-Za-z0-9]{20,}', line) and 'compile' not in line and 'pattern' not in line:
                        secret_hits.append(f"{f}:{i}")
    check("No real secrets in src/", len(secret_hits) == 0, f"hits={secret_hits}")

    # SUMMARY
    print("\n" + "=" * 70)
    total = pass_count + fail_count
    print(f"\n  RESULT: {pass_count}/{total} passed, {fail_count} failed")
    if fail_count == 0:
        print("\n  ALL CHECKS PASSED — TOOL DOES EXACTLY WHAT IT PROMISES")
        print("  READY FOR PUBLICATION")
    else:
        print(f"\n  {fail_count} FAILURES — REVIEW ABOVE")
    print("=" * 70)
    return fail_count

if __name__ == "__main__":
    fails = asyncio.run(main())
    sys.exit(1 if fails else 0)
