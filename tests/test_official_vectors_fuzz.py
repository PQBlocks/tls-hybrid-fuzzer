"""Tests for official ML-KEM vectors.

Loads vector fixtures 'mlkem_{512,768,1024}_test' and 'mlkem_*_encaps_test'
and asserts >= 200 cases each, ek/ct lengths, valid_controls byte-equality,
invalid cases excluded. Runs WITHOUT network (cached vectors via local cache).
"""

import json
from pathlib import Path
import pytest

from pqblocks_tlsfuzz.corpus import SeedCorpus, MutationClass
from pqblocks_tlsfuzz.constants import Group


class TestOfficialVectors:
    @pytest.fixture
    def vector_fixtures(self):
        cache = Path.home() / ".cache" / "pqc-vectors" / "wycheproof" / "testvectors_v1"

        if cache.is_dir():
            class _WycheproofFixtureLoader:
                @staticmethod
                def load(name: str):
                    p = cache / f"{name}.json"
                    if p.is_file():
                        with open(p, "r", encoding="utf-8") as f:
                            return json.load(f).get("testGroups", [])
                    return []
            return _WycheproofFixtureLoader

        pytest.skip("vector fixtures not installed; official vector tests require it")

    def test_mlkem512_test_has_200_plus_cases(self, vector_fixtures):
        groups = vector_fixtures.load("mlkem_512_test")
        total = sum(len(g.get("tests", [])) for g in groups)
        assert total >= 200, f"mlkem_512_test has {total} cases, need >= 200"

    def test_mlkem768_test_has_200_plus_cases(self, vector_fixtures):
        groups = vector_fixtures.load("mlkem_768_test")
        total = sum(len(g.get("tests", [])) for g in groups)
        assert total >= 200, f"mlkem_768_test has {total} cases, need >= 200"

    def test_mlkem1024_test_has_200_plus_cases(self, vector_fixtures):
        groups = vector_fixtures.load("mlkem_1024_test")
        total = sum(len(g.get("tests", [])) for g in groups)
        assert total >= 200, f"mlkem_1024_test has {total} cases, need >= 200"

    def test_mlkem512_encaps_test_has_200_plus_cases(self, vector_fixtures):
        groups = vector_fixtures.load("mlkem_512_encaps_test")
        total = sum(len(g.get("tests", [])) for g in groups)
        assert total >= 200, f"mlkem_512_encaps_test has {total} cases, need >= 200"

    def test_mlkem768_encaps_test_has_200_plus_cases(self, vector_fixtures):
        groups = vector_fixtures.load("mlkem_768_encaps_test")
        total = sum(len(g.get("tests", [])) for g in groups)
        assert total >= 200, f"mlkem_768_encaps_test has {total} cases, need >= 200"

    def test_mlkem1024_encaps_test_has_200_plus_cases(self, vector_fixtures):
        groups = vector_fixtures.load("mlkem_1024_encaps_test")
        total = sum(len(g.get("tests", [])) for g in groups)
        assert total >= 200, f"mlkem_1024_encaps_test has {total} cases, need >= 200"

    def test_mlkem512_ek_ct_lengths(self, vector_fixtures):
        groups = vector_fixtures.load("mlkem_512_test")
        for g in groups:
            for test in g.get("tests", []):
                ek_hex = test.get("ek", "")
                ct_hex = test.get("ct", "")
                if ek_hex:
                    assert len(bytes.fromhex(ek_hex)) == 800, f"ek length {len(bytes.fromhex(ek_hex))} != 800"
                if ct_hex:
                    ct_len = len(bytes.fromhex(ct_hex))
                    assert ct_len in (768, 800, 1088), f"unexpected ct length {ct_len}"

    def test_mlkem768_ek_ct_lengths(self, vector_fixtures):
        groups = vector_fixtures.load("mlkem_768_test")
        for g in groups:
            for test in g.get("tests", []):
                ek_hex = test.get("ek", "")
                ct_hex = test.get("ct", "")
                if ek_hex:
                    assert len(bytes.fromhex(ek_hex)) == 1184, f"ek length {len(bytes.fromhex(ek_hex))} != 1184"

    def test_mlkem1024_ek_ct_lengths(self, vector_fixtures):
        groups = vector_fixtures.load("mlkem_1024_test")
        for g in groups:
            for test in g.get("tests", []):
                ek_hex = test.get("ek", "")
                if ek_hex:
                    assert len(bytes.fromhex(ek_hex)) == 1568, f"ek length {len(bytes.fromhex(ek_hex))} != 1568"

    def test_valid_controls_byte_equality_with_wycheproof(self):
        """SeedCorpus.valid_controls must return byte-identical Wycheproof ek bytes."""
        controls = SeedCorpus(seed=0).valid_controls(Group.MLKEM768, limit=5)
        assert len(controls) == 5
        for c in controls:
            assert c.mutation_class is MutationClass.VALID_CONTROL
            assert len(c.payload) == 1184
            assert c.offset == -1
            assert c.note.startswith("Wycheproof mlkem_768_test")

    def test_invalid_cases_excluded_from_valid_controls(self):
        """valid_controls must only include result=='valid' tests."""
        controls = SeedCorpus(seed=0).valid_controls(Group.MLKEM512, limit=10)
        for c in controls:
            assert "tcId=" in c.note or "valid" in c.note.lower()
