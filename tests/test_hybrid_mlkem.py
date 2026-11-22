import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from pqblocks_tls import fuzz_tls_handshake
import pytest

# Minimal test case for hybrid ML-KEM-768 fuzzer coverage
def test_hybrid_mlkem_handshake_minimal():
    results = fuzz_tls_handshake(
        algorithms=("X25519", "ML-KEM-768"),
        iterations=1,
        max_latency_ms=50
    )
    assert results.all_passed()