"""PEM/DER throwaway certificate harness (slice S14)."""

from __future__ import annotations

from pathlib import Path

from pqblocks_tlsfuzz.harness import generate_harness_keypair


def generate_throwaway_certs(dir_path: Path | str) -> dict[str, Path]:
    """Generate a complete throwaway CA + leaf keypair and write to disk.

    Writes ca.pem, ca.key, leaf.pem, leaf.key (and .der variants) into
    ``dir_path``. Returns a dict mapping names to Path objects.
    """
    return generate_harness_keypair(dir_path)