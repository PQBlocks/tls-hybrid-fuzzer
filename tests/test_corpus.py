"""Tests for corpus.py — hybrid boundary derivation offsets per RFC 10024 §4.1/4.2."""

import dataclasses
import hashlib
import random
from itertools import islice

import pytest
from hypothesis import given, settings, strategies as st
from pqblocks_tlsfuzz import corpus as corpus_mod
from pqblocks_tlsfuzz.corpus import SeedCorpus, hybrid_boundary_offsets
from pqblocks_tlsfuzz.constants import Group, GroupRegistry
from pqblocks_tlsfuzz.errors import CorpusError


class TestHybridBoundaryOffsets:
    """HYBRID_BOUNDARY_SHIFT offsets derived from GroupSpec per RFC 10024 §4.1."""

    def test_hybrid_boundary_offsets_x25519mlkem768(self):
        """X25519MLKEM768 hybrid group: {ek_len−1, ek_len, ek_len+1, point_len−1, point_len, point_len+1}."""
        corpus = SeedCorpus()
        mutations = corpus.systematic(Group.X25519MLKEM768)

        spec = GroupRegistry().get(Group.X25519MLKEM768)
        assert spec.mlkem_ek_len == 1184
        assert spec.ecdhe_point_len == 32

        # Pure ML-KEM offsets for hybrids: {mlkem_ek_len−1, mlkem_ek_len, mlkem_ek_len+1}
        # HYBRID_BOUNDARY_SHIFT: {mlkem_ek_len−1, mlkem_ek_len, mlkem_ek_len+1} and {point_len−1, point_len, point_len+1}
        expected_offsets = {
            spec.mlkem_ek_len - 1,  # 1183
            spec.mlkem_ek_len,      # 1184
            spec.mlkem_ek_len + 1,  # 1185
            spec.ecdhe_point_len - 1,  # 31
            spec.ecdhe_point_len,      # 32
            spec.ecdhe_point_len + 1,  # 33
        }

        actual_offsets = {m.offset for m in mutations if m.mutation_class.name == "HYBRID_BOUNDARY_SHIFT"}

        assert actual_offsets == expected_offsets, f"Expected offsets {expected_offsets}, got {actual_offsets}"

    def test_hybrid_boundary_offsets_secp256r1mlkem768(self):
        """SECP256R1MLKEM768 hybrid group: {ek_len−1, ek_len, ek_len+1, point_len−1, point_len, point_len+1}."""
        corpus = SeedCorpus()
        mutations = corpus.systematic(Group.SECP256R1MLKEM768)

        spec = GroupRegistry().get(Group.SECP256R1MLKEM768)
        assert spec.mlkem_ek_len == 1184
        assert spec.ecdhe_point_len == 65

        expected_offsets = {
            spec.mlkem_ek_len - 1,  # 1183
            spec.mlkem_ek_len,      # 1184
            spec.mlkem_ek_len + 1,  # 1185
            spec.ecdhe_point_len - 1,  # 64
            spec.ecdhe_point_len,      # 65
            spec.ecdhe_point_len + 1,  # 66
        }

        actual_offsets = {m.offset for m in mutations if m.mutation_class.name == "HYBRID_BOUNDARY_SHIFT"}

        assert actual_offsets == expected_offsets, f"Expected offsets {expected_offsets}, got {actual_offsets}"

    def test_hybrid_boundary_offsets_secp384r1mlkem1024(self):
        """SECP384R1MLKEM1024 hybrid group: {ek_len−1, ek_len, ek_len+1, point_len−1, point_len, point_len+1}."""
        corpus = SeedCorpus()
        mutations = corpus.systematic(Group.SECP384R1MLKEM1024)

        spec = GroupRegistry().get(Group.SECP384R1MLKEM1024)
        assert spec.mlkem_ek_len == 1568
        assert spec.ecdhe_point_len == 97

        expected_offsets = {
            spec.mlkem_ek_len - 1,  # 1567
            spec.mlkem_ek_len,      # 1568
            spec.mlkem_ek_len + 1,  # 1569
            spec.ecdhe_point_len - 1,  # 96
            spec.ecdhe_point_len,      # 97
            spec.ecdhe_point_len + 1,  # 98
        }

        actual_offsets = {m.offset for m in mutations if m.mutation_class.name == "HYBRID_BOUNDARY_SHIFT"}

        assert actual_offsets == expected_offsets, f"Expected offsets {expected_offsets}, got {actual_offsets}"

    def test_pure_mlkem512_boundary_offsets(self):
        """MLKEM512 pure group: {ek_len/2, ek_len−1, ek_len}."""
        corpus = SeedCorpus()
        mutations = corpus.systematic(Group.MLKEM512)

        spec = GroupRegistry().get(Group.MLKEM512)
        assert spec.mlkem_ek_len == 800
        assert spec.ecdhe_point_len == 0

        # Pure ML-KEM: {ek_len/2, ek_len−1, ek_len}
        expected_offsets = {
            spec.mlkem_ek_len // 2,  # 400
            spec.mlkem_ek_len - 1,    # 799
            spec.mlkem_ek_len,        # 800
        }

        actual_offsets = {m.offset for m in mutations if m.mutation_class.name == "HYBRID_BOUNDARY_SHIFT"}

        assert actual_offsets == expected_offsets, f"Expected offsets {expected_offsets}, got {actual_offsets}"

    def test_pure_mlkem768_boundary_offsets(self):
        """MLKEM768 pure group: {ek_len/2, ek_len−1, ek_len}."""
        corpus = SeedCorpus()
        mutations = corpus.systematic(Group.MLKEM768)

        spec = GroupRegistry().get(Group.MLKEM768)
        assert spec.mlkem_ek_len == 1184
        assert spec.ecdhe_point_len == 0

        # Pure ML-KEM: {ek_len/2, ek_len−1, ek_len}
        expected_offsets = {
            spec.mlkem_ek_len // 2,  # 592
            spec.mlkem_ek_len - 1,    # 1183
            spec.mlkem_ek_len,        # 1184
        }

        actual_offsets = {m.offset for m in mutations if m.mutation_class.name == "HYBRID_BOUNDARY_SHIFT"}

        assert actual_offsets == expected_offsets, f"Expected offsets {expected_offsets}, got {actual_offsets}"

    def test_pure_mlkem1024_boundary_offsets(self):
        """MLKEM1024 pure group: {ek_len/2, ek_len−1, ek_len}."""
        corpus = SeedCorpus()
        mutations = corpus.systematic(Group.MLKEM1024)

        spec = GroupRegistry().get(Group.MLKEM1024)
        assert spec.mlkem_ek_len == 1568
        assert spec.ecdhe_point_len == 0

        # Pure ML-KEM: {ek_len/2, ek_len−1, ek_len}
        expected_offsets = {
            spec.mlkem_ek_len // 2,  # 784
            spec.mlkem_ek_len - 1,    # 1567
            spec.mlkem_ek_len,        # 1568
        }

        actual_offsets = {m.offset for m in mutations if m.mutation_class.name == "HYBRID_BOUNDARY_SHIFT"}

        assert actual_offsets == expected_offsets, f"Expected offsets {expected_offsets}, got {actual_offsets}"

    def test_hybrid_boundary_shift_per_spec(self):
        """Verify all hybrid groups have correct offset derivation per spec."""
        hybrid_groups = [
            Group.X25519MLKEM768,
            Group.SECP256R1MLKEM768,
            Group.SECP384R1MLKEM1024,
        ]

        for group in hybrid_groups:
            corpus = SeedCorpus()
            mutations = corpus.systematic(group)

            spec = GroupRegistry().get(group)
            assert spec.is_hybrid

            # Extract all HYBRID_BOUNDARY_SHIFT offsets
            offsets = {m.offset for m in mutations if m.mutation_class.name == "HYBRID_BOUNDARY_SHIFT"}

            # Should have exactly 6 offsets: {ek_len−1, ek_len, ek_len+1} and {point_len−1, point_len, point_len+1}
            assert len(offsets) == 6, f"Expected 6 offsets for {group}, got {len(offsets)}"

            # Verify offset ranges (spec §2.3 line 391: union of both boundary bands)
            expected = {
                spec.mlkem_ek_len - 1, spec.mlkem_ek_len, spec.mlkem_ek_len + 1,
                spec.ecdhe_point_len - 1, spec.ecdhe_point_len, spec.ecdhe_point_len + 1,
            }
            assert offsets == expected, f"Expected {expected}, got {offsets}"
            assert min(offsets) == min(expected)
            assert max(offsets) == max(expected)

    def test_pure_mlkem_boundary_shift_per_spec(self):
        """Verify all pure ML-KEM groups have correct offset derivation per spec."""
        pure_mlkem_groups = [
            Group.MLKEM512,
            Group.MLKEM768,
            Group.MLKEM1024,
        ]

        for group in pure_mlkem_groups:
            corpus = SeedCorpus()
            mutations = corpus.systematic(group)

            spec = GroupRegistry().get(group)
            assert not spec.is_hybrid
            assert spec.ecdhe_point_len == 0

            # Extract all HYBRID_BOUNDARY_SHIFT offsets
            offsets = {m.offset for m in mutations if m.mutation_class.name == "HYBRID_BOUNDARY_SHIFT"}

            # Should have exactly 3 offsets: {ek_len/2, ek_len−1, ek_len}
            assert len(offsets) == 3, f"Expected 3 offsets for {group}, got {len(offsets)}"

            # Verify offset ranges
            assert spec.mlkem_ek_len // 2 in offsets
            assert spec.mlkem_ek_len - 1 in offsets
            assert spec.mlkem_ek_len in offsets


class TestHybridBoundaryDerivationEdges:
    """S2 edge cases + negative tests for the HYBRID_BOUNDARY_SHIFT derivation."""

    def test_derivation_sorted_unique_ints_for_all_groups(self):
        """Derivation returns a sorted tuple of unique positive ints for every registry group."""
        registry = GroupRegistry()
        for group in Group:
            spec = registry.get(group)
            offsets = hybrid_boundary_offsets(spec)
            assert isinstance(offsets, tuple)
            assert all(isinstance(o, int) for o in offsets)
            assert list(offsets) == sorted(offsets), f"{group}: offsets not sorted"
            assert len(set(offsets)) == len(offsets), f"{group}: duplicate offsets"
            assert all(o > 0 for o in offsets), f"{group}: non-positive offset"

    def test_derivation_matches_spec_formula_hybrid(self):
        """Hybrid groups: exactly {ek_len−1, ek_len, ek_len+1, point_len−1, point_len, point_len+1}."""
        registry = GroupRegistry()
        for group in (Group.X25519MLKEM768, Group.SECP256R1MLKEM768, Group.SECP384R1MLKEM1024):
            spec = registry.get(group)
            ek, pt = spec.mlkem_ek_len, spec.ecdhe_point_len
            assert hybrid_boundary_offsets(spec) == (
                min(ek - 1, pt - 1), ek - 1, ek, ek + 1, pt - 1, pt, pt + 1,
            ) if ek - 1 <= pt - 1 else (
                pt - 1, pt, pt + 1, ek - 1, ek, ek + 1,
            )
            # canonical expected set regardless of ordering
            assert set(hybrid_boundary_offsets(spec)) == {ek - 1, ek, ek + 1, pt - 1, pt, pt + 1}

    def test_derivation_matches_spec_formula_pure(self):
        """Pure ML-KEM groups: exactly {ek_len//2, ek_len−1, ek_len}."""
        registry = GroupRegistry()
        for group in (Group.MLKEM512, Group.MLKEM768, Group.MLKEM1024):
            spec = registry.get(group)
            ek = spec.mlkem_ek_len
            assert set(hybrid_boundary_offsets(spec)) == {ek // 2, ek - 1, ek}

    def test_systematic_unknown_group_raises_corpus_error(self):
        """Negative: unknown group must raise CorpusError, never silently return empty."""
        corpus = SeedCorpus()
        with pytest.raises(CorpusError):
            corpus.systematic("not-a-real-group")

    def test_systematic_offsets_within_share_bounds(self):
        """Every emitted HYBRID_BOUNDARY_SHIFT offset must be a valid index into the key_share."""
        registry = GroupRegistry()
        for group in Group:
            spec = registry.get(group)
            corpus = SeedCorpus()
            mutations = corpus.systematic(group)
            boundary = [m for m in mutations if m.mutation_class.name == "HYBRID_BOUNDARY_SHIFT"]
            assert boundary, f"{group}: no HYBRID_BOUNDARY_SHIFT mutations emitted"
            ids = set()
            for m in boundary:
                assert 0 < m.offset <= spec.client_share_len, (
                    f"{group}: offset {m.offset} outside (0, {spec.client_share_len}]"
                )
                assert len(m.payload) == spec.client_share_len, (
                    f"{group}: payload length {len(m.payload)} != client_share_len {spec.client_share_len}"
                )
                assert m.id.startswith(f"{group.value}-HYBRID_BOUNDARY_SHIFT-")
                ids.add(m.id)
            assert len(ids) == len(boundary), f"{group}: duplicate mutation ids"

    def test_systematic_deterministic_for_same_seed(self):
        """R9: same seed ⇒ bit-identical corpus (ids and payloads)."""
        for group in Group:
            a = SeedCorpus(seed=1234).systematic(group)
            b = SeedCorpus(seed=1234).systematic(group)
            assert [ (m.id, m.offset, m.payload) for m in a ] == [ (m.id, m.offset, m.payload) for m in b ]

    def test_systematic_mutation_metadata(self):
        """Each HYBRID_BOUNDARY_SHIFT mutation carries class, group, seed, structural note."""
        corpus = SeedCorpus(seed=7)
        mutations = corpus.systematic(Group.X25519MLKEM768)
        for m in mutations:
            assert m.mutation_class.name == "HYBRID_BOUNDARY_SHIFT"
            assert m.group == Group.X25519MLKEM768
            assert m.seed == 7
            assert isinstance(m.structural, dict)
            assert isinstance(m.note, str) and m.note


# ---------------------------------------------------------------------------
# Slice S4: full corpus API (mutation classes, deterministic fan-out, streams)
# ---------------------------------------------------------------------------

class TestS4MutationTypes:
    def test_mutation_class_has_all_thirteen_members(self):
        """spec §1.4: 12 mutation classes + VALID_CONTROL, uppercase names / lowercase values."""
        expected = {
            "TRUNCATED": "truncated",
            "OVERSIZED": "oversized",
            "BITFLIP": "bitflip",
            "GARBAGE_FILL": "garbage_fill",
            "BOUNDARY_OFF_BY_ONE": "boundary_off_by_one",
            "WRONG_GROUP_BYTES": "wrong_group_bytes",
            "DUPLICATE_SHARE": "duplicate_share",
            "MISSING_SHARE": "missing_share",
            "LIST_TRUNCATION": "list_truncation",
            "HYBRID_BOUNDARY_SHIFT": "hybrid_boundary_shift",
            "OVERSIZE_RECORD": "oversize_record",
            "REORDERED_GROUPS": "reordered_groups",
            "VALID_CONTROL": "valid_control",
        }
        mc = corpus_mod.MutationClass
        assert issubclass(mc, str)
        assert {m.name: m.value for m in mc} == expected

    def test_key_share_mutation_is_frozen_and_validates_payload(self):
        """spec §1.4 frozen dataclass; E5: non-bytes payload raises CorpusError naming the field."""
        KSM = corpus_mod.KeyShareMutation
        m = KSM(
            id="mlkem768-truncated-0", group=Group.MLKEM768,
            mutation_class=corpus_mod.MutationClass.TRUNCATED,
            seed=0, offset=0, payload=b"a",
        )
        assert dataclasses.is_dataclass(m)
        with pytest.raises(dataclasses.FrozenInstanceError):
            m.offset = 1
        for bad in ("abc", 123, None):
            with pytest.raises(CorpusError, match="payload"):
                KSM(
                    id="x", group=Group.MLKEM768,
                    mutation_class=corpus_mod.MutationClass.TRUNCATED,
                    seed=0, offset=0, payload=bad,
                )

    def test_type_confusion_group_argument_raises_corpus_error(self):
        """E5: int group (513) must raise CorpusError naming the group, never silently coerce."""
        with pytest.raises(CorpusError):
            GroupRegistry().get(513)
        with pytest.raises(CorpusError):
            SeedCorpus().systematic(513)


class TestS4TruncatedSweep:
    def test_truncated_sweep_unique_ids(self):
        """E3: every offset 0..ek_len-1 yields a unique TRUNCATED mutation for ML-KEM-768."""
        mutations = SeedCorpus().systematic(
            Group.MLKEM768, classes=(corpus_mod.MutationClass.TRUNCATED,),
        )
        assert len(mutations) == 1184
        ids = [m.id for m in mutations]
        assert len(set(ids)) == len(ids)
        assert [len(m.payload) for m in mutations] == list(range(1184))
        assert all(m.mutation_class is corpus_mod.MutationClass.TRUNCATED for m in mutations)

    def test_boundary_off_by_one_offsets(self):
        """E4: ek_len-1/ek_len(+1 where in-bounds) offsets present for hybrid and pure groups."""
        for group in (Group.X25519MLKEM768, Group.SECP256R1MLKEM768, Group.MLKEM768, Group.MLKEM1024):
            spec = GroupRegistry().get(group)
            mutations = SeedCorpus().systematic(
                group, classes=(corpus_mod.MutationClass.BOUNDARY_OFF_BY_ONE,),
            )
            offsets = {m.offset for m in mutations}
            assert spec.mlkem_ek_len - 1 in offsets
            assert spec.mlkem_ek_len in offsets
            if spec.mlkem_ek_len + 1 <= spec.client_share_len:
                assert spec.mlkem_ek_len + 1 in offsets

    def test_hybrid_boundary_shift_class_metadata(self):
        """E7: HYBRID_BOUNDARY_SHIFT systematic mutations keep their class/group/seed metadata."""
        corpus = SeedCorpus(seed=11)
        mutations = corpus.systematic(Group.SECP384R1MLKEM1024)
        assert mutations
        for m in mutations:
            assert m.mutation_class is corpus_mod.MutationClass.HYBRID_BOUNDARY_SHIFT
            assert m.group is Group.SECP384R1MLKEM1024
            assert m.seed == 11
            assert m.offset > 0


class TestS4SplitMix64:
    @staticmethod
    def _reference_stream(seed):
        """Independent SplitMix64 finalizer (transcribed from the algorithm, not product code)."""
        mask = (1 << 64) - 1
        gamma = 0x9E3779B97F4A7C15
        z = seed & mask
        while True:
            z = (z + gamma) & mask
            x = z
            x = ((x ^ (x >> 30)) * 0xBF58476D1CE4E5B9) & mask
            x = ((x ^ (x >> 27)) * 0x94D049BB133111EB) & mask
            yield x ^ (x >> 31)

    def test_splitmix64_matches_independent_reference(self):
        """SplitMix64 stream matches an independently transcribed reference for 8 draws."""
        reference = self._reference_stream(0xDEADBEEF)
        stream = corpus_mod.SplitMix64(0xDEADBEEF)
        for _ in range(8):
            assert stream.next_u64() == next(reference)

    def test_fanout_seed_matches_reference(self):
        """Worker seed i = first SplitMix64 draw of (seed XOR i) per spec §2.3 line 386."""
        for i in range(6):
            reference = self._reference_stream(42 ^ i)
            assert corpus_mod.splitmix64_fanout(42, i) == next(reference)

    def test_seed_fanout_no_collisions(self):
        """E13: 64 workers × seed 42; 100k fan-out seeds unique; ids unique and deterministic."""
        seeds = [corpus_mod.splitmix64_fanout(42, i) for i in range(100_000)]
        assert len(set(seeds)) == 100_000
        workers = [corpus_mod.splitmix64_fanout(42, i) for i in range(64)]
        assert len(set(workers)) == 64

        def ids():
            return [m.id for m in corpus_mod.iter_corpus(
                (Group.MLKEM768,),
                (corpus_mod.MutationClass.TRUNCATED,),
                100_000, 42,
            )]

        a = ids()
        b = ids()
        assert a == b
        assert len(set(a)) == 100_000


class TestS4IterCorpus:
    def test_iter_corpus_is_lazy(self):
        """F16: O(1) memory — a 10M-probe campaign is yielded lazily, not materialized."""
        it = corpus_mod.iter_corpus(
            (Group.MLKEM512, Group.MLKEM768),
            (corpus_mod.MutationClass.TRUNCATED,),
            10_000_000, 0,
        )
        assert not isinstance(it, (list, tuple))
        first = list(islice(it, 3))
        assert len(first) == 3
        assert all(isinstance(m, corpus_mod.KeyShareMutation) for m in first)

    def test_iter_corpus_empty_inputs_rejected(self):
        """E1: empty groups/classes/iterations raise CorpusError with no iteration."""
        with pytest.raises(CorpusError):
            list(corpus_mod.iter_corpus(
                (), (corpus_mod.MutationClass.TRUNCATED,), 10, 0))
        with pytest.raises(CorpusError):
            list(corpus_mod.iter_corpus(
                (Group.MLKEM768,), (), 10, 0))
        with pytest.raises(CorpusError):
            list(corpus_mod.iter_corpus(
                (Group.MLKEM768,), (corpus_mod.MutationClass.TRUNCATED,), 0, 0))

    def test_golden_ids_seed_zero(self):
        """Golden ids for seed=0, independently re-derived from SplitMix64 + the id formula."""
        got = [m.id for m in islice(corpus_mod.iter_corpus(
            (Group.MLKEM768,), (corpus_mod.MutationClass.TRUNCATED,), 5, 0), 5)]

        reference = TestS4SplitMix64._reference_stream(0)
        expected = []
        for seq in range(5):
            u = next(reference)
            rng = random.Random(u)
            base = rng.randbytes(1184)
            offset = u % 1184
            payload = base[:offset]
            digest = hashlib.sha256(payload).hexdigest()[:8]
            expected.append(f"mlkem768-TRUNCATED-{seq:010d}-{digest}")
        assert got == expected

    def test_random_with_rng_is_deterministic(self):
        """spec §1.4 random(group, count, rng): same rng seed ⇒ identical mutations."""
        a = SeedCorpus().random(Group.MLKEM768, 5, random.Random(7))
        b = SeedCorpus().random(Group.MLKEM768, 5, random.Random(7))
        c = SeedCorpus().random(Group.MLKEM768, 5, random.Random(8))
        assert [m.id for m in a] == [m.id for m in b]
        assert [m.id for m in a] != [m.id for m in c]
        assert len({m.id for m in a}) == 5

    def test_unique_id_assertion_helper(self):
        """Unique-id assertion raises CorpusError listing the duplicated id."""
        dup = corpus_mod.KeyShareMutation(
            id="mlkem768-truncated-0", group=Group.MLKEM768,
            mutation_class=corpus_mod.MutationClass.TRUNCATED,
            seed=0, offset=0, payload=b"a",
        )
        corpus_mod.assert_unique_ids([dup])
        with pytest.raises(CorpusError, match="mlkem768-truncated-0"):
            corpus_mod.assert_unique_ids([dup, dup, dup])


class TestS4Properties:
    """F3 property: seeded fan-out is deterministic and collision-free over random seeds."""

    @settings(max_examples=50, deadline=None)
    @given(
        seed=st.integers(min_value=0, max_value=2**63 - 1),
        count=st.integers(min_value=1, max_value=20),
    )
    def test_iter_corpus_ids_unique_and_deterministic(self, seed, count):
        groups = (Group.MLKEM512, Group.X25519MLKEM768)
        classes = (corpus_mod.MutationClass.TRUNCATED, corpus_mod.MutationClass.BOUNDARY_OFF_BY_ONE)

        def ids():
            return [m.id for m in islice(corpus_mod.iter_corpus(groups, classes, count, seed), count)]

        first = ids()
        assert len(set(first)) == count
        assert first == ids()


class TestS4ValidControls:
    """VALID_CONTROL mutations are anchored to published Wycheproof ek bytes."""

    def test_valid_controls_loads_wycheproof_ek(self):
        controls = SeedCorpus(seed=3).valid_controls(Group.MLKEM768, limit=3)
        assert len(controls) == 3
        assert all(c.mutation_class is corpus_mod.MutationClass.VALID_CONTROL for c in controls)
        assert all(len(c.payload) == 1184 for c in controls)
        assert all(c.note.startswith("Wycheproof mlkem_768_test") for c in controls)
        assert len({c.id for c in controls}) == 3

    def test_valid_controls_zero_limit_is_empty(self):
        assert SeedCorpus().valid_controls(Group.MLKEM512, limit=0) == []

    def test_iter_corpus_valid_control_class_uses_fixtures(self):
        mutations = list(corpus_mod.iter_corpus(
            (Group.MLKEM1024,), (corpus_mod.MutationClass.VALID_CONTROL,), 2, 0,
        ))
        assert [m.mutation_class for m in mutations] == [
            corpus_mod.MutationClass.VALID_CONTROL,
            corpus_mod.MutationClass.VALID_CONTROL,
        ]
        assert all(len(m.payload) == 1568 for m in mutations)
        assert len({m.id for m in mutations}) == 2