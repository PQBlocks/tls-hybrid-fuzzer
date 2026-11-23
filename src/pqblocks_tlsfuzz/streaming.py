import json
import os
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from pqblocks_tlsfuzz.corpus import (
    KeyShareMutation,
    MutationClass,
    SeedCorpus,
    iter_corpus,
)
from pqblocks_tlsfuzz.errors import CorpusError
from pqblocks_tlsfuzz.constants import Group, GroupRegistry, GroupSpec
from pqblocks_tlsfuzz.transport import HandshakeOutcome, OutcomeClass, ScriptablePeer
from pqblocks_tlsfuzz.wire import encode_client_hello


class CorpusStream:
    """CorpusStream wraps iter_corpus for streaming use (F16, S10)."""

    def __init__(
        self,
        groups: list[Group],
        classes: list[MutationClass],
        iterations: int,
        seed: int,
        *,
        fpe_fixture_dir: any = None,
    ) -> None:
        if not groups:
            raise CorpusError("iter_corpus: groups must be non-empty")
        if not classes:
            raise CorpusError("iter_corpus: classes must be non-empty")
        if iterations <= 0:
            raise CorpusError("iter_corpus: iterations must be >= 1")
        if not isinstance(seed, int) or isinstance(seed, bool):
            raise CorpusError("seed must be an int")
        if not isinstance(iterations, int) or isinstance(iterations, bool):
            raise CorpusError("iterations must be an int")
        self.groups = groups
        self.classes = classes
        self.iterations = iterations
        self.seed = seed
        self.fpe_fixture_dir = fpe_fixture_dir
        self._corpus = SeedCorpus(fixtures_dir=fpe_fixture_dir, seed=seed)

    def __iter__(self) -> Iterator[KeyShareMutation]:
        yield from iter_corpus(
            self.groups,
            self.classes,
            self.iterations,
            self.seed,
            fpe_fixture_dir=self.fpe_fixture_dir,
        )

    def random(
        self,
        group: Group,
        count: int,
        _rng: any = None,
    ) -> list[KeyShareMutation]:
        """Emit count random mutations from a seeded stream (spec §1.4).

        When ``_rng`` is omitted, SeedCorpus uses the OS CSPRNG so no caller
        can influence key/sign/encrypt randomness. Tests may pass ``_rng``
        explicitly for deterministic replay.
        """
        if count < 0:
            raise CorpusError("random: count must be >= 0")
        return self._corpus.random(group, count, _rng)

    def systematic(
        self,
        group: Group,
        *,
        classes: list[MutationClass] | None = None,
    ) -> list[KeyShareMutation]:
        """Emit systematic mutations for group."""
        return self._corpus.systematic(group, classes=classes)


class ReportStream:
    """ReportStream writes JSONL with flush every 64 outcomes (F15, S10)."""

    def __init__(self, path: Path, flush_every: int = 64) -> None:
        if flush_every <= 0:
            raise ValueError("flush_every must be positive")
        self.path = path
        self.flush_every = flush_every
        self._count = 0
        self._file = open(path, "w", encoding="utf-8")

    def flush(self) -> None:
        self._file.flush()

    def write(self, outcome: HandshakeOutcome) -> None:
        """Write one outcome as JSONL."""
        line = json.dumps(
            {
                "mutation_id": outcome.mutation_id,
                "outcome": outcome.outcome.value,
                "latency_ms": outcome.latency_ms,
                "alert_description": outcome.alert_description,
                "bytes_captured": outcome.bytes_captured,
                "negotiated_group": outcome.negotiated_group,
                "detail": outcome.detail,
            },
            separators=(",", ":"),
        )
        self._file.write(line + "\n")
        self._count += 1
        if self._count % self.flush_every == 0:
            self.flush()

    def __enter__(self) -> "ReportStream":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.flush()
        self._file.close()