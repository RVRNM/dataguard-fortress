"""v0.4 Orchestrator E2E test."""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.config import Config
from src.orchestrator import DataGuardOrchestrator


async def main():
    print("=== DataGuard v0.4 — Orchestrator E2E ===")
    config = Config()
    orch = DataGuardOrchestrator(config)
    await orch.start()

    # Test 1: Normal
    r = await orch.process_request("default", b"Hello world")
    print(f"  [1] Normal: forward={r.forward}, level={r.classification.level.value}, tenant={r.tenant_id}")

    # Test 2: PII-heavy
    r = await orch.process_request("default", b"SSN: 123-45-6789 CC: 4111-1111-1111-1111")
    print(f"  [2] PII: forward={r.forward}, level={r.classification.level.value}, density={r.classification.pii_density:.2f}")

    # Test 3: Internal
    r = await orch.process_request("default", b"Internal memo: salary review")
    print(f"  [3] Internal: level={r.classification.level.value}, reasons={r.classification.reasons}")

    # Test 4: Empty body
    r = await orch.process_request("default", b"")
    print(f"  [4] Empty: level={r.classification.level.value}")

    # Test 5: Tenant
    r = await orch.process_request("some-tenant", b"Hello")
    print(f"  [5] Tenant: id={r.tenant_id}, rate_ok={not r.rate_limited}")

    print(f"\n  Running: {orch.is_running()}")
    await orch.stop()
    print("\n=== v0.4 ORCHESTRATOR PASSED ===")


if __name__ == "__main__":
    asyncio.run(main())
