import pytest
from unittest.mock import patch
from pqblocks_tls import fuzz_tls_handshake, FuzzFailure, FuzzResults, InvalidParameterError, MemoryLimitError

# Property test: round-trip (incremental == full) for single spin flip
def test_property_round_trip():
    # Run fuzzer with 1 iteration to test single flip
    results = fuzz_tls_handshake(
        algorithms=("X25519", "ML-KEM-768"),
        iterations=1,
        max_latency_ms=50,
        seed=42
    )
    # With 1 iteration, passed should be 1, failed should be 0
    assert results.passed == 1
    assert results.failed == 0
    assert results.all_passed() == True

# Property test: idempotence (same parameters = same result)
def test_property_idempotence():
    results1 = fuzz_tls_handshake(
        algorithms=("X25519", "ML-KEM-768"),
        iterations=10,
        max_latency_ms=50,
        seed=99
    )
    results2 = fuzz_tls_handshake(
        algorithms=("X25519", "ML-KEM-768"),
        iterations=10,
        max_latency_ms=50,
        seed=99
    )
    # Results should be identical (same seed)
    assert results1.passed == results2.passed
    assert results1.failed == results2.failed
    assert results1.failures == results2.failures
    assert results1.total_iterations == results2.total_iterations
    assert results1.elapsed_ms == results2.elapsed_ms

# Property test: seed determinism (same seed = same output)
def test_property_seed_determinism():
    # Run twice with same seed
    r1 = fuzz_tls_handshake(
        algorithms=("X25519", "ML-KEM-768"),
        iterations=5,
        max_latency_ms=50,
        seed=123
    )
    r2 = fuzz_tls_handshake(
        algorithms=("X25519", "ML-KEM-768"),
        iterations=5,
        max_latency_ms=50,
        seed=123
    )
    # Hashes should match (bit-identical)
    import hashlib
    hash1 = hashlib.sha256(str(r1).encode()).hexdigest()
    hash2 = hashlib.sha256(str(r2).encode()).hexdigest()
    assert hash1 == hash2

# Negative test: invalid algorithms tuple
def test_negative_invalid_algorithms():
    with pytest.raises(InvalidParameterError):
        fuzz_tls_handshake(algorithms=("X25519",), iterations=1, max_latency_ms=50)

# Negative test: zero iterations
def test_negative_zero_iterations():
    with pytest.raises(InvalidParameterError):
        fuzz_tls_handshake(algorithms=("X25519", "ML-KEM-768"), iterations=0, max_latency_ms=50)

# Negative test: negative seed
def test_negative_seed():
    with pytest.raises(InvalidParameterError):
        fuzz_tls_handshake(algorithms=("X25519", "ML-KEM-768"), iterations=1, max_latency_ms=50, seed=-1)

# Negative test: invalid max_latency_ms
def test_negative_max_latency():
    with pytest.raises(InvalidParameterError):
        fuzz_tls_handshake(algorithms=("X25519", "ML-KEM-768"), iterations=1, max_latency_ms=0)

# Negative test: invalid seed type
def test_invalid_seed_type():
    with pytest.raises(InvalidParameterError):
        fuzz_tls_handshake(algorithms=("X25519", "ML-KEM-768"), iterations=1, max_latency_ms=50, seed="invalid")

# Negative test: memory limit exceeded (use very low limit)
def test_memory_limit():
    with patch('pqblocks_tls.time.perf_counter') as mock_perf_counter:
        # Make the elapsed time exceed max_latency_ms (1ms) to trigger MemoryLimitError
        # The test sets max_latency_ms=1, so we need elapsed_iter_ms > 1ms
        mock_perf_counter.side_effect = [0.0, 0.0, 2.0]  # 2ms elapsed > 1ms budget
        
        with pytest.raises(MemoryLimitError):
            fuzz_tls_handshake(
                algorithms=("X25519", "ML-KEM-768"),
                iterations=1,
                max_latency_ms=1,  # very low limit
                seed=42
            )