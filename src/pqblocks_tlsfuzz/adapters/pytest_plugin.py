"""Pytest plugin adapter (slice S19).

pytest11 entry-point: ``--pq-tlsfuzz-endpoint=host:port`` option, one
parametrized test per failed mutation class group, JSONL archive artifact.
Framework middleware hook: ``@pytest.fixture`` with graceful no-op when flag
absent. Import-safe: no third-party deps beyond pytest hookspecs (stdlib).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest


def pytest_addoption(parser: Any) -> None:
    """Add ``--pq-tlsfuzz-endpoint`` CLI option to pytest."""
    group = parser.getgroup("pqblocks-tlsfuzz")
    group.addoption(
        "--pq-tlsfuzz-endpoint",
        action="store",
        default=None,
        help="host:port of a running TLS endpoint for pqblocks-tlsfuzz fuzz tests",
    )
    group.addoption(
        "--pq-tlsfuzz-iterations",
        action="store",
        type=int,
        default=100,
        help="number of fuzz iterations per parametrized test (default: 100)",
    )
    group.addoption(
        "--pq-tlsfuzz-seed",
        action="store",
        type=int,
        default=0,
        help="seed for deterministic fuzz campaign (default: 0)",
    )
    group.addoption(
        "--pq-tlsfuzz-jsonl",
        action="store",
        default=None,
        help="write fuzz outcomes as JSONL to this path",
    )


def pytest_configure(config: Any) -> None:
    """Register the pqblocks-tlsfuzz marker and store endpoint config."""
    config.addinivalue_line(
        "markers",
        "pq_tlsfuzz: mark a test as requiring a pqblocks-tlsfuzz endpoint",
    )


class PQTLsFuzzPytestPlugin:
    """Pytest plugin that wires endpoint-driven fuzz tests into the session."""

    def __init__(self, config: Any) -> None:
        self.config = config
        self.endpoint = config.getoption("--pq-tlsfuzz-endpoint")
        self.iterations = config.getoption("--pq-tlsfuzz-iterations")
        self.seed = config.getoption("--pq-tlsfuzz-seed")
        self.jsonl_path = config.getoption("--pq-tlsfuzz-jsonl")
        self._outcomes: list[dict[str, Any]] = []

    def endpoint_configured(self) -> bool:
        """Return True if --pq-tlsfuzz-endpoint was supplied."""
        return self.endpoint is not None

    def record_outcome(self, mutation_id: str, outcome: str, detail: str = "") -> None:
        """Record one fuzz outcome for JSONL archival."""
        self._outcomes.append({
            "mutation_id": mutation_id,
            "outcome": outcome,
            "detail": detail,
        })

    def write_jsonl(self, path: Path | str | None = None) -> Path | None:
        """Write recorded outcomes as JSONL. Returns path written, or None if no outcomes."""
        target = Path(path) if path else (Path(self.jsonl_path) if self.jsonl_path else None)
        if target is None or not self._outcomes:
            return None
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(target, "w", encoding="utf-8") as f:
            for o in self._outcomes:
                f.write(json.dumps(o, separators=(",", ":")))
                f.write("\n")
        return target


def pytest_collection_modifyitems(config: Any, items: list[Any]) -> None:
    """Hook: skip pq_tlsfuzz-marked tests when no endpoint is configured."""
    endpoint = config.getoption("--pq-tlsfuzz-endpoint")
    if endpoint is None:
        skip_marker = pytest.mark.skip(reason="--pq-tlsfuzz-endpoint not provided")
        for item in items:
            if item.get_closest_marker("pq_tlsfuzz"):
                item.add_marker(skip_marker)


def pytest_generate_tests(metafunc: Any) -> None:
    """Parametrize pq_tlsfuzz-marked tests over failed mutation class groups.

    When ``--pq-tlsfuzz-endpoint`` is set, each test marked with ``pq_tlsfuzz``
    is parametrized once per mutation class group so every failed class group
    gets its own parametrized test invocation. When the flag is absent, tests
    are left untouched (graceful no-op).
    """
    endpoint = metafunc.config.getoption("--pq-tlsfuzz-endpoint")
    if endpoint is None:
        return
    if "pq_tlsfuzz" not in metafunc.fixturenames:
        return

    # One parametrization per mutation class group (spec S19 contract).
    groups = [
        "truncated",
        "oversized",
        "bitflip",
        "garbage_fill",
        "boundary_off_by_one",
        "wrong_group_bytes",
        "duplicate_share",
        "missing_share",
        "list_truncation",
        "oversize_record",
        "reordered_groups",
    ]
    ids: list[str] = []
    argvalues: list[Any] = []
    for g in groups:
        ids.append(g)
        argvalues.append(g)
    pytest.parametrize(
        "mutation_group",
        argvalues,
        ids=ids,
        indirect=False,
    )(metafunc)


@pytest.fixture
def pq_tlsfuzz_endpoint(request: Any) -> str | None:
    """Fixture returning the configured endpoint, or None if not set.

    Graceful no-op: tests using this fixture without the flag get None and
    should skip themselves rather than fail.
    """
    return request.config.getoption("--pq-tlsfuzz-endpoint")


@pytest.fixture
def pq_tlsfuzz_iterations(request: Any) -> int:
    """Fixture returning the configured iteration count."""
    return request.config.getoption("--pq-tlsfuzz-iterations")


@pytest.fixture
def pq_tlsfuzz_seed(request: Any) -> int:
    """Fixture returning the configured seed."""
    return request.config.getoption("--pq-tlsfuzz-seed")