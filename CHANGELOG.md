# Changelog - pqblocks-tls

All notable changes to this project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-22

### Added
- Initial public release of `pqblocks-tls` (TLS 1.3 Hybrid Handshake Fuzzer).
- Dual hybrid key exchange fuzzing engine combining X25519 with FIPS 203 ML-KEM-768.
- Comprehensive failure taxonomy capturing timeouts, decapsulation errors, protocol violations, and memory boundary violations.
- Deterministic pseudo-random generation with seed reproducibility.
- Full unit, integration, metamorphic property, and official vector test coverage.
