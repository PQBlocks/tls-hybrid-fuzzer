# Practical Use Cases & Integration Patterns — pqblocks-tls

Examples of deploying `pqblocks-tls` in testing pipelines, CI/CD, and regression monitoring.

---

## 1. CI/CD Pipeline Protocol Regression Gate

Incorporate hybrid handshake fuzzing into continuous integration to prevent performance degradation or cryptographic regressions:

```python
import sys
from pqblocks_tls import fuzz_tls_handshake, FuzzResults

def test_tls_hybrid_ci_gate():
    results: FuzzResults = fuzz_tls_handshake(
        algorithms=("X25519", "ML-KEM-768"),
        iterations=500,
        max_latency_ms=25,
        seed=1337,
    )
    assert results.all_passed(), f"Fuzzing detected {results.failed} failures"
    print("CI Gate: 500 hybrid handshakes passed cleanly")

if __name__ == "__main__":
    test_tls_hybrid_ci_gate()
```

---

## 2. Latency Budget Verification

Verify that post-quantum handshake overhead conforms to strict microservice latency SLAs:

```python
from pqblocks_tls import fuzz_tls_handshake, MemoryLimitError

try:
    results = fuzz_tls_handshake(
        algorithms=("X25519", "ML-KEM-768"),
        iterations=100,
        max_latency_ms=2,  # Strict SLA threshold
    )
    print(f"Handshake latency compliant: {results.elapsed_ms} ms total")
except MemoryLimitError as err:
    print(f"SLA violation detected: {err}")
```
