"""Corpus generation for pqblocks_tlsfuzz (slices S2 + S4).

Implements HYBRID_BOUNDARY_SHIFT offset derivation per RFC 10024 §4.1 and
spec/spec.md §2.3 line 391 (S2), plus the full mutation-class taxonomy,
``SeedCorpus`` API, SplitMix64 fan-out and the O(1)-memory ``iter_corpus``
generator (S4, spec §1.4).

SplitMix64 here is a DETERMINISTIC stream-splitter for reproducible fuzz
campaigns (F3 / E13) — it is not a security RNG and produces no secrets.
"""

from __future__ import annotations

import hashlib
import os
import random
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Iterator, Sequence

from pqblocks_tlsfuzz.constants import Group, GroupRegistry, GroupSpec
from pqblocks_tlsfuzz.errors import CorpusError


class MutationClass(str, Enum):
    """Mutation class identifiers (spec §1.4: 12 classes + VALID_CONTROL)."""

    TRUNCATED = "truncated"
    OVERSIZED = "oversized"
    BITFLIP = "bitflip"
    GARBAGE_FILL = "garbage_fill"
    BOUNDARY_OFF_BY_ONE = "boundary_off_by_one"
    WRONG_GROUP_BYTES = "wrong_group_bytes"
    DUPLICATE_SHARE = "duplicate_share"
    MISSING_SHARE = "missing_share"
    LIST_TRUNCATION = "list_truncation"
    HYBRID_BOUNDARY_SHIFT = "hybrid_boundary_shift"
    OVERSIZE_RECORD = "oversize_record"
    REORDERED_GROUPS = "reordered_groups"
    VALID_CONTROL = "valid_control"


#: Classes that mutate bytes of the key_exchange region (offset >= 0).
BYTE_CLASSES: tuple[MutationClass, ...] = (
    MutationClass.TRUNCATED,
    MutationClass.OVERSIZED,
    MutationClass.BITFLIP,
    MutationClass.GARBAGE_FILL,
    MutationClass.BOUNDARY_OFF_BY_ONE,
    MutationClass.WRONG_GROUP_BYTES,
    MutationClass.HYBRID_BOUNDARY_SHIFT,
)

#: Classes that mutate the negotiation structure (offset = -1).
STRUCTURAL_CLASSES: tuple[MutationClass, ...] = (
    MutationClass.DUPLICATE_SHARE,
    MutationClass.MISSING_SHARE,
    MutationClass.LIST_TRUNCATION,
    MutationClass.OVERSIZE_RECORD,
    MutationClass.REORDERED_GROUPS,
)

#: Classes sampled by ``random()`` (VALID_CONTROL is drawn from fixtures only).
RANDOM_CLASSES: tuple[MutationClass, ...] = BYTE_CLASSES + STRUCTURAL_CLASSES


@dataclass(frozen=True)
class KeyShareMutation:
    """One key-share mutation instance (spec §1.4).

    ``id`` is ``f"{group}-{cls}-{discriminator}"``; existing S2 systematic ids
    keep the ``{group}-HYBRID_BOUNDARY_SHIFT-{offset}`` form.
    """

    id: str
    group: Group
    mutation_class: MutationClass
    seed: int
    offset: int
    payload: bytes
    structural: dict[str, Any] = field(default_factory=dict)
    note: str = ""

    def __post_init__(self) -> None:
        # E5: hostile inputs fail loudly at construction, naming the field.
        # bytearray is accepted here so wire.py's encoder remains the layer that
        # enforces strict ``bytes`` (test_wire.py::test_payload_must_be_bytes).
        if not isinstance(self.payload, (bytes, bytearray)):
            raise CorpusError(
                f"KeyShareMutation payload must be bytes, got {type(self.payload).__name__}"
            )
        if not isinstance(self.offset, int):
            raise CorpusError(
                f"KeyShareMutation offset must be int, got {type(self.offset).__name__}"
            )


def assert_unique_ids(mutations: Sequence[KeyShareMutation]) -> None:
    """Raise CorpusError on the first duplicated mutation id (S4 unique-id assertion)."""
    seen: set[str] = set()
    for mutation in mutations:
        if mutation.id in seen:
            raise CorpusError(f"duplicate mutation id: {mutation.id}")
        seen.add(mutation.id)


def hybrid_boundary_offsets(spec: GroupSpec) -> tuple[int, ...]:
    """Return HYBRID_BOUNDARY_SHIFT offsets derived from a GroupSpec.

    Per spec §2.3 line 391 / RFC 10024 §4.1 layout:
      - Hybrid groups: {mlkem_ek_len−1, mlkem_ek_len, mlkem_ek_len+1} and
                       {point_len−1, point_len, point_len+1}
      - Pure ML-KEM groups: {ek_len/2, ek_len−1, ek_len}

    Returns a sorted tuple of unique positive integer offsets.
    """
    ek = spec.mlkem_ek_len
    if spec.is_hybrid:
        pt = spec.ecdhe_point_len
        raw = (ek - 1, ek, ek + 1, pt - 1, pt, pt + 1)
    else:
        raw = (ek // 2, ek - 1, ek)
    return tuple(sorted(set(raw)))


# --- SplitMix64: deterministic stream fan-out (spec §2.3 line 386 / E13) ---

_MASK64 = (1 << 64) - 1
_GAMMA = 0x9E3779B97F4A7C15


class SplitMix64:
    """Deterministic SplitMix64 u64 stream — a stream splitter, not a crypto RNG."""

    def __init__(self, seed: int) -> None:
        self._state = seed & _MASK64

    def next_u64(self) -> int:
        """Advance the stream and return the next 64-bit value."""
        self._state = (self._state + _GAMMA) & _MASK64
        z = self._state
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & _MASK64
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & _MASK64
        return z ^ (z >> 31)


def splitmix64_fanout(seed: int, index: int) -> int:
    """First SplitMix64 draw of the worker substream ``seed XOR index`` (§2.3)."""
    return SplitMix64(seed ^ index).next_u64()


# --- systematic offset derivation per mutation class ---


def _offsets_for_class(cls: MutationClass, spec: GroupSpec) -> tuple[int, ...]:
    """Offsets emitted by ``systematic()`` for one class/group pair."""
    if cls is MutationClass.TRUNCATED:
        # E3: sweep every byte offset of the key_exchange region.
        return tuple(range(spec.client_share_len))
    if cls is MutationClass.HYBRID_BOUNDARY_SHIFT:
        return hybrid_boundary_offsets(spec)
    if cls is MutationClass.BOUNDARY_OFF_BY_ONE:
        ek, ct = spec.mlkem_ek_len, spec.mlkem_ct_len
        return tuple(sorted({o for o in (ek - 1, ek, ek + 1, ct - 1, ct, ct + 1) if o > 0}))
    if cls is MutationClass.OVERSIZED:
        return (spec.mlkem_ek_len + 1, spec.mlkem_ek_len + 2)
    if cls in STRUCTURAL_CLASSES or cls is MutationClass.VALID_CONTROL:
        return (-1,)
    # BITFLIP / GARBAGE_FILL / WRONG_GROUP_BYTES: FIPS boundary bands.
    if spec.is_hybrid:
        return hybrid_boundary_offsets(spec)
    ek = spec.mlkem_ek_len
    return (ek // 2, ek - 1, ek)


def _payload_for_class(
    cls: MutationClass,
    base: bytes,
    offset: int,
    rng: random.Random,
    spec: GroupSpec,
) -> bytes:
    """Apply one class's byte-level transform to a full-length base payload."""
    if cls is MutationClass.TRUNCATED:
        return base[:offset]
    if cls is MutationClass.OVERSIZED:
        return base + rng.randbytes(max(offset, 0))
    if cls is MutationClass.BITFLIP and base:
        buf = bytearray(base)
        pos = offset % len(buf)
        buf[pos] ^= 1 << (offset % 8)
        return bytes(buf)
    if cls in (MutationClass.GARBAGE_FILL, MutationClass.WRONG_GROUP_BYTES):
        return rng.randbytes(len(base))
    if cls is MutationClass.BOUNDARY_OFF_BY_ONE:
        return base[: min(offset, len(base))]
    return base  # HYBRID_BOUNDARY_SHIFT and structural classes carry the full share


class SeedCorpus:
    """Deterministic seed corpus (spec §1.4)."""

    def __init__(self, fixtures_dir: Any = None, seed: int = 0) -> None:
        self.fixtures_dir = fixtures_dir
        self.seed = seed
        self._systematic_cache: dict[tuple[Group, tuple[str, ...]], list[KeyShareMutation]] = {}

    @staticmethod
    def _load_vector_loader() -> Any:
        """Load vector fixtures from directory or cache."""
        import json
        import os
        from pathlib import Path

        fixtures_dir = os.environ.get("PQTLSFUZZ_FIXTURES_DIR")
        candidates = []
        if fixtures_dir:
            candidates.append(Path(fixtures_dir))
        candidates.extend([
            Path.home() / ".cache" / "pqc-vectors" / "wycheproof" / "testvectors_v1",
            Path.home() / ".cache" / "pqc-vectors" / "wycheproof",
        ])

        for c in candidates:
            if c.is_dir() and (c / "mlkem_768_test.json").is_file():
                class _WycheproofLoader:
                    @staticmethod
                    def load(name: str):
                        target = c / f"{name}.json"
                        if target.is_file():
                            with open(target, "r", encoding="utf-8") as f:
                                return json.load(f).get("testGroups", [])
                        return []
                return _WycheproofLoader

        raise CorpusError(
            "valid_controls: vector fixtures unavailable; set PQTLSFUZZ_FIXTURES_DIR "
            "to a directory of Wycheproof ML-KEM fixture files"
        )

    def valid_controls(self, group: Group | str, limit: int) -> list[KeyShareMutation]:
        """Return up to ``limit`` untouched Wycheproof ek bytes as VALID_CONTROL mutations."""
        spec = GroupRegistry().get(group)
        if limit <= 0:
            return []
        vector_set = {800: "mlkem_512_test", 1184: "mlkem_768_test", 1568: "mlkem_1024_test"}.get(
            spec.mlkem_ek_len
        )
        if vector_set is None:  # pragma: no cover - all registry groups map
            raise CorpusError(f"valid_controls: no vector set for group {group!r}")

        loader = self._load_vector_loader()
        controls: list[KeyShareMutation] = []
        for loader_group in loader.load(vector_set):
            for test in loader_group.get("tests", []):
                if test.get("result") != "valid":
                    continue
                ek_hex = test.get("ek")
                if not isinstance(ek_hex, str):
                    continue
                ek = bytes.fromhex(ek_hex)
                if len(ek) != spec.mlkem_ek_len:
                    continue
                tc_id = test.get("tcId")
                controls.append(
                    KeyShareMutation(
                        id=f"{spec.group.value}-VALID_CONTROL-{tc_id}",
                        group=spec.group,
                        mutation_class=MutationClass.VALID_CONTROL,
                        seed=self.seed,
                        offset=-1,
                        payload=ek,
                        structural={},
                        note=f"Wycheproof {vector_set} tcId={tc_id}",
                    )
                )
                if len(controls) >= limit:
                    return controls
        if not controls:
            raise CorpusError(
                "valid_controls: no valid Wycheproof ek found; set PQTLSFUZZ_FIXTURES_DIR"
            )
        return controls

    def systematic(
        self,
        group: Group | str,
        *,
        classes: Sequence[MutationClass] | None = None,
    ) -> list[KeyShareMutation]:
        """Emit systematic mutations for ``group``.

        Default ``classes`` is HYBRID_BOUNDARY_SHIFT only — the contract the
        S2 tests were written against. S4 adds the ``classes`` parameter for
        the TRUNCATED sweep (E3) and the other mandated classes (E4/E7).
        """
        spec = GroupRegistry().get(group)
        resolved = tuple(classes) if classes else (MutationClass.HYBRID_BOUNDARY_SHIFT,)
        for cls in resolved:
            if not isinstance(cls, MutationClass):
                raise CorpusError(f"systematic: unknown mutation class {cls!r}")
        cache_key = (spec.group, tuple(cls.name for cls in resolved))
        if cache_key in self._systematic_cache:
            return list(self._systematic_cache[cache_key])

        rng = random.Random(self.seed)
        base = bytes(rng.randrange(256) for _ in range(spec.client_share_len))
        mutations: list[KeyShareMutation] = []
        for cls in resolved:
            for offset in _offsets_for_class(cls, spec):
                payload = _payload_for_class(cls, base, offset, rng, spec)
                discriminator = str(offset)
                mid = f"{spec.group.value}-{cls.name}-{discriminator}"
                mutations.append(
                    KeyShareMutation(
                        id=mid,
                        group=spec.group,
                        mutation_class=cls,
                        seed=self.seed,
                        offset=offset,
                        payload=payload,
                        structural=(
                            {"boundary": "hybrid" if spec.is_hybrid else "pure_mlkem"}
                            if cls is MutationClass.HYBRID_BOUNDARY_SHIFT
                            else {}
                        ),
                        note=f"{cls.name} boundary offset {offset} for {spec.group.value}",
                    )
                )
        assert_unique_ids(mutations)
        self._systematic_cache[cache_key] = list(mutations)
        return list(mutations)

    def random(
        self,
        group: Group | str,
        count: int,
        _rng: random.Random | None = None,
    ) -> list[KeyShareMutation]:
        """Emit ``count`` random mutations from a seeded stream (spec §1.4).

        When ``_rng`` is omitted, the OS CSPRNG seeds the stream so no caller
        can influence key/sign/encrypt randomness. Tests may pass ``_rng``
        explicitly for deterministic replay.
        """
        spec = GroupRegistry().get(group)
        if count < 0:
            raise CorpusError("random: count must be >= 0")
        if _rng is None:
            _rng = random.Random(int.from_bytes(os.urandom(8), "big"))
        mutations: list[KeyShareMutation] = []
        for _ in range(count):
            cls = _rng.choice(RANDOM_CLASSES)
            u = _rng.getrandbits(64)
            base = _rng.randbytes(spec.client_share_len)
            offset = -1 if cls in STRUCTURAL_CLASSES else u % spec.client_share_len
            payload = _payload_for_class(cls, base, offset, _rng, spec)
            mutations.append(
                KeyShareMutation(
                    id=f"{spec.group.value}-{cls.name}-{u:016x}",
                    group=spec.group,
                    mutation_class=cls,
                    seed=self.seed,
                    offset=offset,
                    payload=payload,
                    structural={},
                    note=f"random {cls.name} for {spec.group.value}",
                )
            )
        assert_unique_ids(mutations)
        return mutations


def iter_corpus(
    groups: Sequence[Group],
    classes: Sequence[MutationClass],
    iterations: int,
    seed: int,
    *,
    fpe_fixture_dir: Any = None,
) -> Iterator[KeyShareMutation]:
    """Yield ``iterations`` mutations lazily (F16: O(1) memory).

    Same ``(groups, classes, iterations, seed)`` ⇒ same sequence. Each probe's
    bytes come from one SplitMix64 draw, so worker streams fan out without
    materializing the corpus.
    """
    if not groups:
        raise CorpusError("iter_corpus: groups must be non-empty")
    if not classes:
        raise CorpusError("iter_corpus: classes must be non-empty")
    if iterations <= 0:
        raise CorpusError("iter_corpus: iterations must be >= 1")

    registry = GroupRegistry()
    stream = SplitMix64(seed)
    corpus = SeedCorpus(fixtures_dir=fpe_fixture_dir, seed=seed)
    for seq in range(iterations):
        u = stream.next_u64()
        group = groups[seq % len(groups)]
        cls = classes[seq % len(classes)]
        spec = registry.get(group)
        rng = random.Random(u)
        base = rng.randbytes(spec.client_share_len)
        offset = -1 if cls in STRUCTURAL_CLASSES else u % spec.client_share_len

        if cls is MutationClass.VALID_CONTROL:
            controls = corpus.valid_controls(group, 1)
            control = controls[0]
            mutation = KeyShareMutation(
                id=f"{spec.group.value}-VALID_CONTROL-{seq:010d}",
                group=spec.group,
                mutation_class=cls,
                seed=seed,
                offset=control.offset,
                payload=control.payload,
                structural=dict(control.structural),
                note=f"VALID_CONTROL seq={seq} ({control.note})",
            )
        else:
            payload = _payload_for_class(cls, base, offset, rng, spec)
            digest = hashlib.sha256(payload).hexdigest()[:8]
            mutation = KeyShareMutation(
                id=f"{spec.group.value}-{cls.name}-{seq:010d}-{digest}",
                group=spec.group,
                mutation_class=cls,
                seed=seed,
                offset=offset,
                payload=payload,
                structural={},
                note=f"{cls.name} seq={seq} group={spec.group.value}",
            )
        yield mutation
