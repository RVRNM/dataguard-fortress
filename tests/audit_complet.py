"""Audit fonctionnel complet DataGuard Fortress v0.4"""

import asyncio
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, r"C:\Users\HP\TheSpace\dataguard-fortress")

results = []


def check(name, passed, detail=""):
    status = "PASS" if passed else "FAIL"
    results.append((name, passed, detail))
    print(f"  [{status}] {name}: {detail}")


async def main():
    print("=" * 70)
    print("  AUDIT FONCTIONNEL COMPLET DataGuard Fortress v0.4")
    print("=" * 70)

    # 1. PII SCRUBBING
    print("\n[1] PII SCRUBBING (52+ presets)")
    from src.scrubber import PIIScrubber
    s = PIIScrubber(min_confidence=0.0)
    check("52+ presets loaded", s.preset_count >= 52, f"{s.preset_count} presets")

    pii_tests = [
        ("email", "Contact: john.doe@example.com", "john.doe@example.com"),
        ("ssn", "SSN: 123-45-6789", "123-45-6789"),
        ("phone_fr", "Tel: +33612345678", "+33612345678"),
        ("phone_us", "Call (555) 123-4567", "(555) 123-4567"),
        ("cc_visa", "Card: 4111-1111-1111-1111", "4111-1111-1111-1111"),
        ("cc_mc", "Card: 5500-0000-0000-0004", "5500-0000-0000-0004"),
        ("openai_key", "Key: sk-TEST-REDACTED", "sk-abcdefghijkl"),
        ("aws_key", "AWS: TEST_AWS_KEY", "TEST_AWS_KEY"),
        ("github_token", "token: TEST_GITHUB_TOKEN", "TEST_GITHUB_TOKEN"),
        ("stripe_key", "TEST_SECRET_KEY "TEST_SECRET_KEY
        ("btc", "BTC: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"),
        ("eth", "ETH: 0x742d35Cc6634C0532925a3b844Bc9e7595f2bD28", "0x742d35Cc"),
        ("ipv4", "IP: 192.168.1.100", "192.168.1.100"),
        ("ipv6", "IP: 2001:0db8:85a3::7334", "2001:db8"),
        ("mrn", "MRN: MRN-12345-67890", "MRN-12345-67890"),
    ]
    for name, text, sensitive in pii_tests:
        r = await s.scrub(text)
        still_here = sensitive[:8] in r.scrubbed_text
        check(f"  {name}", not still_here, f"sensitive {'HIDDEN' if not still_here else 'LEAKED'}")

    # 2. CLASSIFICATION
    print("\n[2] CLASSIFICATION")
    from src.classifier import DataClassifier, SensitivityLevel
    c = DataClassifier()
    for level_name, text, expected in [
        ("PUBLIC", "Hello world, weather is nice", SensitivityLevel.PUBLIC),
        ("INTERNAL", "Internal memo: employee salary review", SensitivityLevel.INTERNAL),
        ("CONFIDENTIAL", "The password is secret123", SensitivityLevel.CONFIDENTIAL),
        ("RESTRICTED", "SSN: 123-45-6789 CC: 4111-1111-1111-1111", SensitivityLevel.RESTRICTED),
    ]:
        r = await c.classify(text)
        check(f"  {level_name}", r.level == expected, f"score={r.score:.2f}")

    # 3. RATE LIMITER
    print("\n[3] RATE LIMITER")
    from src.token_bucket import MemoryTokenBucketBackend, TokenBucket
    backend = MemoryTokenBucketBackend()
    bucket = TokenBucket(backend=backend, key="audit-test", rate=10.0, capacity=5.0)
    acquired = 0
    for _ in range(7):
        if await bucket.try_acquire():
            acquired += 1
    check("Token bucket burst+block", acquired == 5, f"acquired={acquired}")

    from src.sliding_window_ratelimiter import MemoryRateLimiterBackend, SlidingWindowRateLimiter
    sw = SlidingWindowRateLimiter(MemoryRateLimiterBackend(), max_requests=3, window_seconds=60)
    sw_count = 0
    for _ in range(5):
        ok, _ = await sw.check("audit-user")
        if ok:
            await sw.record("audit-user")
            sw_count += 1
    check("Sliding window cap", sw_count == 3, f"allowed={sw_count}")

    # AUDIT LOGGER
    print("\n[4] AUDIT LOGGER")
    from src.audit import AuditEvent, AuditEventType, AuditLogger
    os.makedirs("./tmp_audit", exist_ok=True)
    alog = AuditLogger()
    alog._log_dir = Path("./tmp_audit")
    alog._log_filename = "audit.jsonl"
    await alog.log(AuditEvent(event_type=AuditEventType.REQUEST, upstream="openai.com", method="POST", path="/v1/chat"))
    await alog.log(AuditEvent(event_type=AuditEventType.SCRUB, upstream="openai.com", scrub_count=3))
    await alog.log(AuditEvent(event_type=AuditEventType.PROXY_ERROR, upstream="bad.com", error="timeout"))
    await asyncio.sleep(0.3)
    await alog.aclose()
    lines = open("./tmp_audit/audit.jsonl").readlines() if os.path.exists("./tmp_audit/audit.jsonl") else []
    check("Audit entries written", len(lines) == 3, f"{len(lines)} entries")
    os.remove("./tmp_audit/audit.jsonl") if os.path.exists("./tmp_audit/audit.jsonl") else None
    os.rmdir("./tmp_audit")

    # 5. TENANT MANAGER
    print("\n[5] TENANT MANAGER")
    os.makedirs("./tmp_tenants", exist_ok=True)
    with open("./tmp_tenants/acme.yaml", "w") as f:
        f.write("tenant_id: acme\nname: Acme Corp\nrate_limit:\n  requests_per_second: 20.0\n  burst_size: 100\n  max_concurrent: 50\n  window_seconds: 120\n")
    from src.tenant import TenantManager
    tm = TenantManager(tenants_dir="./tmp_tenants")
    tm.reload()
    check("Tenants loaded", len(tm.list_tenants()) >= 1, f"tenants={tm.list_tenants()}")
    t = tm.get_tenant("acme")
    check("Rate limit read", t.rate_limit.requests_per_second == 20.0, f"rps={t.rate_limit.requests_per_second}")
    check("Default fallback", tm.get_tenant("nonexistent") is not None, "returns default")
    await tm.stop()
    if os.path.exists("./tmp_tenants/acme.yaml"):
        os.remove("./tmp_tenants/acme.yaml")
    if os.path.exists("./tmp_tenants"):
        os.rmdir("./tmp_tenants")

    # 6. ORCHESTRATOR
    print("\n[6] ORCHESTRATOR (full pipeline)")
    from src.config import Config
    from src.orchestrator import DataGuardOrchestrator
    orch = DataGuardOrchestrator(Config())
    await orch.start()
    r = await orch.process_request("default", b"Hello world")
    check("Normal forward", r.forward is True, f"tenant={r.tenant_id}")
    r = await orch.process_request("default", b"SSN: 123-45-6789 CC: 4111-1111-1111-1111 Email: a@b.com")
    check("PII classified RESTRICTED", r.classification.level == SensitivityLevel.RESTRICTED, f"score={r.classification.score:.2f}")
    await orch.stop()

    # 7. PERFORMANCE
    print("\n[7] PERFORMANCE")
    large = "Email: test@e.com " * 10000
    t0 = time.monotonic()
    for _ in range(100):
        await s.scrub(large)
    speed = len(large) * 100 / (time.monotonic() - t0) / 1e6
    check("Scrub speed > 0.5 MB/s", speed > 0.5, f"{speed:.1f} MB/s")

    # SUMMARY
    print("\n" + "=" * 70)
    total = len(results)
    passed = sum(1 for _, p, _ in results if p)
    failed_count = total - passed
    print(f"\n  TOTAL: {passed}/{total} passed, {failed_count} failed")
    if failed_count > 0:
        print("\n  FAILURES:")
        for name, ok, detail in results:
            if not ok:
                print(f"    FAIL {name}: {detail}")
    else:
        print("\n  ALL CHECKS PASSED TOOL DOES EXACTLY WHAT IT PROMISES")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(main())
