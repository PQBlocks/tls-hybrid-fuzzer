# pqblocks-tls

[![Status: Stable](https://img.shields.io/badge/status-Stable-059669.svg)](https://pqblocks.github.io)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Python: >=3.10](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue)](https://pypi.org/project/pqblocks-tls/)

Post-quantum hybrid TLS 1.3 handshake fuzzer and verification harness combining **X25519** and **ML-KEM-768** (FIPS 203).

Part of the **PQBlocks** post-quantum cryptography suite. Maintained by **Govind Dubey** and The PQBlocks Authors under the Apache-2.0 license.

---

## Overview

Modern cryptographic migrations to post-quantum standards require hybrid key establishment to ensure confidentiality against future quantum adversaries while retaining classical security baselines. In TLS 1.3, hybrid key exchange couples a classical elliptic curve key agreement (X25519) with a post-quantum lattice-based key encapsulation mechanism (ML-KEM-768).

`pqblocks-tls` provides a lightweight, deterministic testing and fuzzing harness to validate hybrid TLS 1.3 key exchange behavior, evaluate latency budgets, verify encapsulation/decapsulation round-trips, and catch protocol regressions under diverse execution conditions.

---

## Key Features

- **Standard Cryptography:** Uses verified implementations from `pyca/cryptography` for both X25519 and FIPS 203 ML-KEM-768.
- **Deterministic Fuzzing:** Configurable pseudo-random seed guarantees bit-identical test execution across runs.
- **Latency & Resource Budgeting:** Per-iteration execution timers guard against side-channel latency degradation and timing timeouts.
- **Structured Error Taxonomy:** Categorizes failures into timeouts, decapsulation faults, certificate errors, and protocol violations.
- **Zero Heavyweight Dependencies:** Runs entirely on standard Python with `cryptography>=50.0.1`.

---

## Installation

Install the package via pip:

```bash
pip install pqblocks-tls
```

Or install from source:

```bash
git clone https://github.com/PQBlocks/tls-hybrid-fuzzer.git
cd tls-hybrid-fuzzer
pip install .
```

---

## Quickstart

```python
from pqblocks_tls import fuzz_tls_handshake, FuzzResults

# Execute 1,000 hybrid handshake iterations with a deterministic seed
results: FuzzResults = fuzz_tls_handshake(
    algorithms=("X25519", "ML-KEM-768"),
    iterations=1000,
    max_latency_ms=50,
    seed=42,
)

print(f"Passed: {results.passed}/{results.total_iterations}")
print(f"Elapsed: {results.elapsed_ms} ms")
assert results.all_passed()
```

---

## API Reference

The primary entry point is `fuzz_tls_handshake`.

### Function: `fuzz_tls_handshake`

Executes simulated hybrid TLS 1.3 key exchange handshakes.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `algorithms` | `Tuple[str, str]` | *(Required)* | Algorithm pair; must be exactly `("X25519", "ML-KEM-768")`. |
| `iterations` | `int` | `1000` | Total number of handshake iterations (must be positive integer). |
| `max_latency_ms` | `int` | `50` | Maximum latency threshold in milliseconds permitted per iteration. |
| `seed` | `Optional[int]` | `None` | Integer seed for deterministic RNG. When `None`, uses system CSPRNG. |

**Returns:** `FuzzResults`

**Exceptions:**
- `InvalidParameterError`: Raised when parameters fail validation constraints.
- `MemoryLimitError`: Raised when an iteration exceeds the specified `max_latency_ms`.

---

### Data Models

#### `FuzzResults`

Immutable result container returned by `fuzz_tls_handshake`.

| Attribute | Type | Description |
|---|---|---|
| `passed` | `int` | Number of successful handshake iterations. |
| `failed` | `int` | Number of failed iterations. |
| `failures` | `List[FuzzFailureDetail]` | Forensic details for any failed iteration. |
| `total_iterations` | `int` | Total count of scheduled iterations. |
| `elapsed_ms` | `int` | Execution duration in milliseconds. |
| `all_passed()` | `Callable[[], bool]` | Convenience method returning `True` if `failed == 0`. |

#### `FuzzFailure` (Enum)

| Enum Value | Name | Description |
|---|---|---|
| `HANDSHAKE_TIMEOUT` | `"handshake_timeout"` | Iteration exceeded allowable latency window. |
| `DECAPS_FAILURE` | `"decaps_failure"` | Decapsulated shared secret did not match encapsulated secret. |
| `CERT_VALIDATION_ERROR` | `"cert_validation_error"` | Certificate verification or chain building failed. |
| `PROTOCOL_VIOLATION` | `"protocol_violation"` | Malformed message ordering or unsupported parameters. |
| `CBOM_EMISSION_ERROR` | `"cbom_emission_error"` | Failure during cryptographic bill-of-materials recording. |

---

## Command-Line Interface (`pqblocks-tlsfuzz`)

`pqblocks-tls` includes the `pqblocks-tlsfuzz` command-line tool for wire-level mutation testing and fuzzing of TLS 1.3 ClientHello key shares across 6 post-quantum and hybrid groups (`X25519MLKEM768`, `SecP256r1MLKEM768`, `MLKEM512`, `MLKEM768`, `MLKEM1024`, `X25519`) using 13 mutation classes.

```bash
# Verify local runtime and post-quantum group support
pqblocks-tlsfuzz doctor

# Stream deterministically generated test cases as JSONL
pqblocks-tlsfuzz corpus --group X25519MLKEM768 --limit 10

# Execute mutation fuzzing against a live target
pqblocks-tlsfuzz fuzz --host localhost --port 8443 --group X25519MLKEM768 --count 100 --seed 42
```

---

## Testing & Verification

Run the test suite via pytest:

```bash
pytest tests/ -v
```

See **[TESTING.md](TESTING.md)** and **[VERIFICATION_REPORT.md](VERIFICATION_REPORT.md)** for detailed test inventories and audit records.

---

## Author & Maintainers

- **Govind Dubey** ([govinddubeycse@gmail.com](mailto:govinddubeycse@gmail.com))
- **The PQBlocks Authors** ([https://github.com/PQBlocks](https://github.com/PQBlocks))

---

## License

Licensed under the Apache License, Version 2.0. See **[LICENSE](LICENSE)** and **[NOTICE](NOTICE)**.
