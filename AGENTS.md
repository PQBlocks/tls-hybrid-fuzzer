# Agent Integration Guidelines — pqblocks-tls

Operational context and safety guidelines for automated agents interacting with `pqblocks-tls`.

---

## Capabilities & Constraints

- `pqblocks-tls` executes simulated in-process hybrid handshakes.
- It does **not** bind raw TCP sockets or initiate live network connections.
- Parameter validation enforces exact tuple ordering: `("X25519", "ML-KEM-768")`.
- Execution is completely deterministic when an integer `seed` is provided.
