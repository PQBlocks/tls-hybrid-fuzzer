"""Tests for constants.py — FIPS 203 Table 2/3 + RFC 10024 group registry (slice S1)."""

import pytest

from pqblocks_tlsfuzz.constants import (
    Group,
    GroupSpec,
    GroupRegistry,
    MLKEM512_PARAMS,
    MLKEM768_PARAMS,
    MLKEM1024_PARAMS,
)
from pqblocks_tlsfuzz.errors import CorpusError


class TestMLKEMParameters:
    """FIPS 203 §8 Tables 2–3 parameter transcription."""

    def test_mlkem_512_params(self):
        assert MLKEM512_PARAMS.n == 256
        assert MLKEM512_PARAMS.q == 3329
        assert MLKEM512_PARAMS.k == 2
        assert MLKEM512_PARAMS.eta1 == 3
        assert MLKEM512_PARAMS.eta2 == 2
        assert MLKEM512_PARAMS.du == 10
        assert MLKEM512_PARAMS.dv == 4
        assert MLKEM512_PARAMS.ek_bytes == 800
        assert MLKEM512_PARAMS.dk_bytes == 1632
        assert MLKEM512_PARAMS.ct_bytes == 768
        assert MLKEM512_PARAMS.ss_bytes == 32

    def test_mlkem_768_params(self):
        assert MLKEM768_PARAMS.n == 256
        assert MLKEM768_PARAMS.q == 3329
        assert MLKEM768_PARAMS.k == 3
        assert MLKEM768_PARAMS.eta1 == 2
        assert MLKEM768_PARAMS.eta2 == 2
        assert MLKEM768_PARAMS.du == 10
        assert MLKEM768_PARAMS.dv == 4
        assert MLKEM768_PARAMS.ek_bytes == 1184
        assert MLKEM768_PARAMS.dk_bytes == 2400
        assert MLKEM768_PARAMS.ct_bytes == 1088
        assert MLKEM768_PARAMS.ss_bytes == 32

    def test_mlkem_1024_params(self):
        assert MLKEM1024_PARAMS.n == 256
        assert MLKEM1024_PARAMS.q == 3329
        assert MLKEM1024_PARAMS.k == 4
        assert MLKEM1024_PARAMS.eta1 == 2
        assert MLKEM1024_PARAMS.eta2 == 2
        assert MLKEM1024_PARAMS.du == 11
        assert MLKEM1024_PARAMS.dv == 5
        assert MLKEM1024_PARAMS.ek_bytes == 1568
        assert MLKEM1024_PARAMS.dk_bytes == 3168
        assert MLKEM1024_PARAMS.ct_bytes == 1568
        assert MLKEM1024_PARAMS.ss_bytes == 32

    def test_params_are_frozen(self):
        with pytest.raises(AttributeError):
            MLKEM512_PARAMS.k = 99


class TestGroupSpecParameters:
    """GroupSpec codepoints, ek/ct lengths, hybrid layouts (RFC 10024 §4.1–4.2)."""

    def test_mlkem_512_spec(self):
        spec = GroupRegistry().get(Group.MLKEM512)
        assert spec.group == Group.MLKEM512
        assert spec.codepoint == 0x0200
        assert spec.mlkem_ek_len == 800
        assert spec.mlkem_ct_len == 768
        assert spec.client_share_len == 800
        assert spec.server_share_len == 768
        assert spec.ecdhe_point_len == 0
        assert spec.is_hybrid is False
        assert "draft-ietf-tls-mlkem" in spec.clause
        assert "FIPS 203" in spec.clause

    def test_mlkem_768_spec(self):
        spec = GroupRegistry().get(Group.MLKEM768)
        assert spec.group == Group.MLKEM768
        assert spec.codepoint == 0x0201
        assert spec.mlkem_ek_len == 1184
        assert spec.mlkem_ct_len == 1088
        assert spec.client_share_len == 1184
        assert spec.server_share_len == 1088
        assert spec.ecdhe_point_len == 0
        assert spec.is_hybrid is False

    def test_mlkem_1024_spec(self):
        spec = GroupRegistry().get(Group.MLKEM1024)
        assert spec.group == Group.MLKEM1024
        assert spec.codepoint == 0x0202
        assert spec.mlkem_ek_len == 1568
        assert spec.mlkem_ct_len == 1568
        assert spec.client_share_len == 1568
        assert spec.server_share_len == 1568
        assert spec.ecdhe_point_len == 0
        assert spec.is_hybrid is False

    def test_x25519mlkem768_spec(self):
        spec = GroupRegistry().get(Group.X25519MLKEM768)
        assert spec.group == Group.X25519MLKEM768
        assert spec.codepoint == 0x11EC
        assert spec.mlkem_ek_len == 1184
        assert spec.mlkem_ct_len == 1088
        assert spec.ecdhe_point_len == 32
        assert spec.client_share_len == 1216  # 1184 + 32
        assert spec.server_share_len == 1120  # 1088 + 32
        assert spec.is_hybrid is True
        assert "RFC 10024" in spec.clause

    def test_secp256r1mlkem768_spec(self):
        spec = GroupRegistry().get(Group.SECP256R1MLKEM768)
        assert spec.group == Group.SECP256R1MLKEM768
        assert spec.codepoint == 0x11EB
        assert spec.mlkem_ek_len == 1184
        assert spec.mlkem_ct_len == 1088
        assert spec.ecdhe_point_len == 65
        assert spec.client_share_len == 1249  # 65 + 1184
        assert spec.server_share_len == 1153  # 65 + 1088
        assert spec.is_hybrid is True

    def test_secp384r1mlkem1024_spec(self):
        spec = GroupRegistry().get(Group.SECP384R1MLKEM1024)
        assert spec.group == Group.SECP384R1MLKEM1024
        assert spec.codepoint == 0x11ED
        assert spec.mlkem_ek_len == 1568
        assert spec.mlkem_ct_len == 1568
        assert spec.ecdhe_point_len == 97
        assert spec.client_share_len == 1665  # 97 + 1568
        assert spec.server_share_len == 1665  # 97 + 1568
        assert spec.is_hybrid is True

    def test_hybrid_layout_lengths_from_rfc10024(self):
        """RFC 10024 §4.1–4.2 hybrid layout lengths: 1216/1120/1249/1153/1665/1665."""
        reg = GroupRegistry()
        assert reg.get(Group.X25519MLKEM768).client_share_len == 1216
        assert reg.get(Group.X25519MLKEM768).server_share_len == 1120
        assert reg.get(Group.SECP256R1MLKEM768).client_share_len == 1249
        assert reg.get(Group.SECP256R1MLKEM768).server_share_len == 1153
        assert reg.get(Group.SECP384R1MLKEM1024).client_share_len == 1665
        assert reg.get(Group.SECP384R1MLKEM1024).server_share_len == 1665

    def test_spec_is_frozen(self):
        spec = GroupRegistry().get(Group.MLKEM768)
        with pytest.raises(AttributeError):
            spec.codepoint = 0xFFFF


class TestGroupRegistry:
    """GroupRegistry.get / .all behavior."""

    def test_all_returns_six_groups(self):
        all_specs = GroupRegistry().all()
        assert len(all_specs) == 6
        groups = {s.group for s in all_specs}
        assert groups == {
            Group.MLKEM512,
            Group.MLKEM768,
            Group.MLKEM1024,
            Group.X25519MLKEM768,
            Group.SECP256R1MLKEM768,
            Group.SECP384R1MLKEM1024,
        }

    def test_get_by_enum(self):
        spec = GroupRegistry().get(Group.MLKEM768)
        assert spec.group == Group.MLKEM768

    def test_get_by_string_name(self):
        spec = GroupRegistry().get("mlkem768")
        assert spec.group == Group.MLKEM768

    def test_get_by_string_case_insensitive(self):
        spec = GroupRegistry().get("MLKEM768")
        assert spec.group == Group.MLKEM768

    def test_get_unknown_string_raises_corpus_error(self):
        with pytest.raises(CorpusError) as exc:
            GroupRegistry().get("unknown_group")
        assert "unknown_group" in str(exc.value)

    def test_get_unknown_int_raises_corpus_error(self):
        with pytest.raises(CorpusError):
            GroupRegistry().get(999)

    def test_get_unknown_enum_raises_corpus_error(self):
        with pytest.raises(CorpusError):
            GroupRegistry().get("mlkem2048")


class TestGroupEnum:
    """Group enum values and str-mixin."""

    def test_group_values(self):
        assert Group.MLKEM512 == "mlkem512"
        assert Group.MLKEM768 == "mlkem768"
        assert Group.MLKEM1024 == "mlkem1024"
        assert Group.X25519MLKEM768 == "x25519mlkem768"
        assert Group.SECP256R1MLKEM768 == "secp256r1mlkem768"
        assert Group.SECP384R1MLKEM1024 == "secp384r1mlkem1024"

    def test_group_values_are_strings(self):
        for g in Group:
            assert isinstance(g.value, str)
            assert isinstance(g, str)

    def test_six_groups_total(self):
        assert len(list(Group)) == 6