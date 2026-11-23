# Security Policy — pqblocks-tls

## Supported Versions

Security updates and vulnerability remediation are actively provided for:

| Version | Supported | Notes |
|---|:---:|---|
| `0.1.x` | **Yes** | Stable active track. |

---

## Reporting a Vulnerability

If you discover a security vulnerability or implementation flaw in `pqblocks-tls`, please report it through one of the following channels:

### 1. GitHub Security Advisory (Preferred)
Open a private report under GitHub Security Advisories:  
👉 **[https://github.com/PQBlocks/tls-hybrid-fuzzer/security/advisories/new](https://github.com/PQBlocks/tls-hybrid-fuzzer/security/advisories/new)**

### 2. Direct Author Contact
If you cannot use GitHub Advisories, please contact the maintainer directly:  
- **Author:** Govind Dubey (`govinddubeycse+pqblocks@gmail.com`)
- **Issue Tracker:** [https://github.com/PQBlocks/tls-hybrid-fuzzer/issues](https://github.com/PQBlocks/tls-hybrid-fuzzer/issues)

Please avoid posting unredacted exploit payloads or sensitive key material in public issue threads.

---

## Remediation & Disclosure Timeline

1. **Initial Acknowledgment:** Within **48 hours** of receipt.
2. **Triaging & Reproduction:** Within **5 business days** with severity assigned per CVSS v3.1.
3. **Patch Verification:** Fixes prepared in a private staging branch and validated against regression test suites.
4. **Public Advisory:** Release tagged and advisory published within **30 days** of confirmation.

---

## Scope & Architectural Defenses

This policy covers the core fuzzing logic and memory safety boundaries in `src/pqblocks_tls/`. Cryptographic operations rely on `pyca/cryptography`'s official FIPS 203 ML-KEM-768 and RFC 7748 X25519 primitives. Detailed threat modeling and boundary checks are documented in [SECURITY_NOTES.md](SECURITY_NOTES.md).
