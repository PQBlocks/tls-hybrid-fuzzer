# Testing Strategy & Execution Guide — pqblocks-tls

Comprehensive testing protocols, validation suites, and execution instructions for `pqblocks-tls`.

---

## 1. Testing Philosophy & Scope

The `pqblocks-tls` verification framework ensures stability and conformance across hybrid cryptographic workflows. Handshake fuzzing combines classical curve operations (X25519) with lattice-based key encapsulation (ML-KEM-768). Testing encompasses:

1. **Functional Correctness:** Every valid execution generates valid X25519 public keys, ML-KEM-768 encapsulation keys, and matches shared secrets across both primitives.
2. **Deterministic Reproducibility:** Fixed seeds produce bit-identical test trajectories across repeated executions on different architectures.
3. **Negative & Boundary Validation:** Invalid algorithm pairs, non-positive iteration counts, negative seeds, and sub-millisecond timeout constraints reliably raise expected typed exceptions (`InvalidParameterError`, `MemoryLimitError`).
4. **Metamorphic Properties:** Monotonic iteration counts, non-negative failure counters, and strict invariance under identical inputs.
5. **Standards Compliance:** Conformance tests against FIPS 203 ML-KEM-768 key sizes (1184-byte public key, 1088-byte ciphertext, 32-byte shared secret) and RFC 7748 X25519 key agreements.

---

## 2. Test Suite Architecture

The test suite is organized into three primary modules:

| Test File | Test Cases | Objective |
|---|:---:|---|
| `tests/test_additional_properties.py` | 9 | Parameter boundaries, negative values, types, error message checks, and deterministic seed behavior. |
| `tests/test_hybrid_mlkem.py` | 1 | Basic end-to-end handshake execution and return structure verification. |
| `tests/test_official_vectors.py` | 6 | Conformance tests validating key generation, encapsulation, decapsulation, and shared secret equality. |

---

## 3. Running the Tests

### 3.1 Standard Pytest Execution

```bash
# From package root
pytest tests/ -v
```

### 3.2 Coverage Profiling

```bash
pytest tests/ -v --cov=pqblocks_tls --cov-report=term-missing
```

### 3.3 Isolated Cleanroom Execution

To verify package installation in a pristine virtual environment without local path bindings:

```bash
python3 -m venv /tmp/tls-cleanroom
source /tmp/tls-cleanroom/bin/activate
pip install --upgrade pip
pip install .[test]
pytest tests/ -v
deactivate
rm -rf /tmp/tls-cleanroom
```

---

## 4. Test Results Summary

- **Total Tests:** 16
- **Passed:** 16
- **Failed:** 0
- **Execution Time:** ~0.30 seconds
- **Pass Rate:** 100%
