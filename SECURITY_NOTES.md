# Security Architecture & Threat Model — pqblocks-tls

Defensive posture, boundary invariants, and threat analysis for `pqblocks-tls`.

---

## 1. Scope & Primary Mission

`pqblocks-tls` is a test and verification harness designed to simulate, fuzz, and stress hybrid TLS 1.3 key exchanges. It tests protocol transitions to post-quantum cryptography, specifically combining classical X25519 key exchange with NIST FIPS 203 ML-KEM-768.

---

## 2. Threat Analysis & Mitigations

### 2.1 Cryptographic Algorithm Compromise
- **Threat:** Either classical X25519 is broken by quantum computers (Shor's algorithm) or ML-KEM-768 suffers an unforeseen mathematical vulnerability.
- **Mitigation:** The hybrid model guarantees confidentiality as long as *either* primitive remains uncompromised. Breaking the hybrid handshake requires breaking both discrete logarithms on Curve25519 and Module Learning With Errors (M-LWE).

### 2.2 Side-Channel & Timing Variations
- **Threat:** Timing variations during decapsulation or key agreement allow an eavesdropper to extract secret key bits.
- **Mitigation:** Underlying primitives in `pyca/cryptography` are implemented in constant time using OpenSSL / standard cryptographic C backends.

### 2.3 Denial of Service & Memory Exhaustion
- **Threat:** Excessive iteration counts or malicious unbounded inputs exhaust host system memory.
- **Mitigation:** `fuzz_tls_handshake` implements strict type checking, iteration upper-bound validation, and per-iteration latency thresholds via `max_latency_ms`.
