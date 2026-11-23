"""Tests for wire.py (slice S3).

Emitter/parser for TLS 1.3 record + handshake layers only. No key schedule,
no AEAD, no KEM: the module moves bytes and reports what it saw.

Covers spec §6.2 test_wire.py rows: round-trip (hypothesis >= 500 examples),
HRR (E18), non-TLS response (E17), oversize record (E2/E10 wire half),
unknown alert (E9), malformed server share (E8).
"""

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from pqblocks_tlsfuzz.constants import Group, GroupRegistry
from pqblocks_tlsfuzz.corpus import KeyShareMutation, MutationClass
from pqblocks_tlsfuzz.errors import CorpusError, WireParseError
from pqblocks_tlsfuzz.wire import (
    ALERT_DECODE_ERROR,
    ALERT_FATAL,
    ALERT_HANDSHAKE_FAILURE,
    ALERT_ILLEGAL_PARAMETER,
    ALERT_INTERNAL_ERROR,
    ALERT_RECORD,
    ALERT_WARNING,
    CLIENT_HELLO,
    DEFAULT_SIGNATURE_ALGORITHMS,
    EXT_KEY_SHARE,
    EXT_PSK_KEY_EXCHANGE_MODES,
    EXT_SIGNATURE_ALGORITHMS,
    EXT_SUPPORTED_GROUPS,
    EXT_SUPPORTED_VERSIONS,
    HANDSHAKE_RECORD,
    HRR_MAGIC_RANDOM,
    LEGACY_RECORD_VERSION,
    PSK_DHE_KEY_EXCHANGE_MODE,
    SERVER_HELLO,
    TLS12_VERSION,
    TLS13_VERSION,
    AlertMsg,
    ServerHelloMsg,
    encode_alert,
    encode_client_hello,
    encode_server_hello,
    is_hrr_random,
    parse_alert,
    parse_client_hello,
    parse_server_hello,
)

REGISTRY = GroupRegistry()

ALL_GROUPS = (
    Group.MLKEM512,
    Group.MLKEM768,
    Group.MLKEM1024,
    Group.X25519MLKEM768,
    Group.SECP256R1MLKEM768,
    Group.SECP384R1MLKEM1024,
)


def make_share(payload=b"", *, group=Group.MLKEM768, structural=None, seed=0):
    """Build a KeyShareMutation carrying the given key_exchange payload."""
    return KeyShareMutation(
        id=f"{group.value}-test-{seed}",
        group=group,
        mutation_class=MutationClass.HYBRID_BOUNDARY_SHIFT,
        seed=seed,
        offset=-1,
        payload=payload,
        structural=dict(structural or {}),
    )


def codepoint(group):
    return REGISTRY.get(group).codepoint


class TestConstants:
    """Wire constants are transcribed, not invented (RFC 8446/9846 §5.1, §4.2)."""

    def test_record_and_handshake_content_types(self):
        assert HANDSHAKE_RECORD == 0x16
        assert ALERT_RECORD == 0x15

    def test_handshake_message_types(self):
        assert CLIENT_HELLO == 0x01
        assert SERVER_HELLO == 0x02

    def test_extension_type_codes(self):
        assert EXT_SUPPORTED_GROUPS == 0x000A
        assert EXT_SIGNATURE_ALGORITHMS == 0x000D
        assert EXT_SUPPORTED_VERSIONS == 0x002B
        assert EXT_PSK_KEY_EXCHANGE_MODES == 0x002D
        assert EXT_KEY_SHARE == 0x0033

    def test_versions(self):
        assert TLS12_VERSION == 0x0303
        assert TLS13_VERSION == 0x0304
        assert LEGACY_RECORD_VERSION == 0x0301

    def test_hrr_magic_random_is_sha256_of_hello_retry_request(self):
        """RFC 8446 §4.1.3 special Random value."""
        assert HRR_MAGIC_RANDOM == bytes.fromhex(
            "cf21ad74e59a6111be1d8c021e65b891"
            "c2a211167abb8c5e079e09e2c8a8339c"
        )

    def test_alert_description_codes(self):
        assert ALERT_HANDSHAKE_FAILURE == 40
        assert ALERT_ILLEGAL_PARAMETER == 47
        assert ALERT_DECODE_ERROR == 50
        assert ALERT_INTERNAL_ERROR == 80
        assert (ALERT_WARNING, ALERT_FATAL) == (1, 2)


class TestEncodeClientHello:
    """Emitter: record layer + handshake layer + five extensions."""

    def test_record_header_uses_legacy_record_version(self):
        """RFC 8446 §5.1: initial ClientHello record legacy_record_version 0x0301."""
        buf = encode_client_hello(make_share(b"\x00" * 8), offered_groups=ALL_GROUPS)

        assert buf[0] == HANDSHAKE_RECORD
        assert int.from_bytes(buf[1:3], "big") == LEGACY_RECORD_VERSION

    def test_handshake_body_uses_legacy_version_0303(self):
        """RFC 8446 §4.1.2: ClientHello legacy_version MUST be 0x0303."""
        buf = encode_client_hello(make_share(b"\x00" * 8), offered_groups=ALL_GROUPS)

        handshake = buf[5:]
        assert handshake[0] == CLIENT_HELLO
        assert int.from_bytes(handshake[1:4], "big") == len(handshake) - 4
        assert int.from_bytes(handshake[4:6], "big") == TLS12_VERSION

    def test_legacy_version_override_is_honoured(self):
        buf = encode_client_hello(
            make_share(b"\x00" * 8), offered_groups=ALL_GROUPS, legacy_version=0x0300
        )

        assert int.from_bytes(buf[9:11], "big") == 0x0300

    def test_record_length_matches_fragment(self):
        buf = encode_client_hello(make_share(b"\x11" * 64), offered_groups=ALL_GROUPS)

        assert int.from_bytes(buf[3:5], "big") == len(buf) - 5

    def test_all_five_extensions_present_in_spec_order(self):
        buf = encode_client_hello(make_share(b"\x22" * 64), offered_groups=ALL_GROUPS)
        msg = parse_client_hello(buf)

        assert msg.extension_types == (
            EXT_SUPPORTED_VERSIONS,
            EXT_SUPPORTED_GROUPS,
            EXT_KEY_SHARE,
            EXT_SIGNATURE_ALGORITHMS,
            EXT_PSK_KEY_EXCHANGE_MODES,
        )

    def test_supported_versions_offers_tls13_only(self):
        msg = parse_client_hello(
            encode_client_hello(make_share(b"\x22" * 8), offered_groups=ALL_GROUPS)
        )

        assert msg.supported_versions == (TLS13_VERSION,)

    def test_supported_groups_lists_every_offered_group(self):
        msg = parse_client_hello(
            encode_client_hello(make_share(b"\x22" * 8), offered_groups=ALL_GROUPS)
        )

        assert msg.supported_groups == tuple(codepoint(g) for g in ALL_GROUPS)

    def test_key_share_carries_payload_verbatim(self):
        payload = bytes(range(256)) * 5  # 1280 bytes, non-trivial pattern
        msg = parse_client_hello(
            encode_client_hello(make_share(payload), offered_groups=ALL_GROUPS)
        )

        assert msg.key_share_entries == ((codepoint(Group.MLKEM768), payload),)

    def test_psk_key_exchange_modes_is_psk_dhe_ke(self):
        msg = parse_client_hello(
            encode_client_hello(make_share(b"\x22" * 8), offered_groups=ALL_GROUPS)
        )

        assert msg.psk_key_exchange_modes == (PSK_DHE_KEY_EXCHANGE_MODE,)

    def test_signature_algorithms_not_empty(self):
        msg = parse_client_hello(
            encode_client_hello(make_share(b"\x22" * 8), offered_groups=ALL_GROUPS)
        )

        assert msg.signature_algorithms == DEFAULT_SIGNATURE_ALGORITHMS
        assert len(msg.signature_algorithms) >= 2

    def test_session_id_is_32_bytes_and_deterministic(self):
        first = parse_client_hello(
            encode_client_hello(
                make_share(b"\x22" * 8, seed=7), offered_groups=ALL_GROUPS
            )
        )
        second = parse_client_hello(
            encode_client_hello(
                make_share(b"\x22" * 8, seed=7), offered_groups=ALL_GROUPS
            )
        )
        other = parse_client_hello(
            encode_client_hello(
                make_share(b"\x22" * 8, seed=8), offered_groups=ALL_GROUPS
            )
        )

        assert len(first.legacy_session_id) == 32
        assert first.random == second.random
        assert first.legacy_session_id == second.legacy_session_id
        assert first.random != other.random

    def test_encode_is_deterministic(self):
        share = make_share(b"\xab" * 300)
        first = encode_client_hello(share, offered_groups=ALL_GROUPS)
        second = encode_client_hello(share, offered_groups=ALL_GROUPS)

        assert first == second

    def test_hybrid_group_client_share_length_matches_registry(self):
        """RFC 10024 §4.2 layout lengths must survive the emitter."""
        for group in ALL_GROUPS:
            spec = REGISTRY.get(group)
            payload = bytes(spec.client_share_len)
            msg = parse_client_hello(
                encode_client_hello(make_share(payload, group=group), offered_groups=(group,))
            )

            assert msg.key_share_entries[0][1] == payload
            assert len(msg.key_share_entries[0][1]) == spec.client_share_len


class TestStructuralMutations:
    """Negotiation-structure mutations are expressible through `structural`."""

    def test_missing_share_omits_key_share_extension(self):
        buf = encode_client_hello(
            make_share(b"\x22" * 8, structural={"include_key_share": False}),
            offered_groups=ALL_GROUPS,
        )
        msg = parse_client_hello(buf)

        assert EXT_KEY_SHARE not in msg.extension_types
        assert msg.key_share_entries == ()

    def test_duplicate_share_emits_two_entries(self):
        msg = parse_client_hello(
            encode_client_hello(
                make_share(b"\x22" * 8, structural={"duplicate_key_share": True}),
                offered_groups=ALL_GROUPS,
            )
        )

        assert len(msg.key_share_entries) == 2
        assert msg.key_share_entries[0] == msg.key_share_entries[1]

    def test_list_truncation_replaces_supported_groups(self):
        msg = parse_client_hello(
            encode_client_hello(
                make_share(b"\x22" * 8, structural={"supported_groups": [0x11EC]}),
                offered_groups=ALL_GROUPS,
            )
        )

        assert msg.supported_groups == (0x11EC,)

    def test_reordered_groups_preserves_given_order(self):
        order = [codepoint(g) for g in reversed(ALL_GROUPS)]
        msg = parse_client_hello(
            encode_client_hello(
                make_share(b"\x22" * 8, structural={"supported_groups": order}),
                offered_groups=ALL_GROUPS,
            )
        )

        assert msg.supported_groups == tuple(order)

    def test_wrong_group_bytes_uses_override_in_key_share_entry(self):
        msg = parse_client_hello(
            encode_client_hello(
                make_share(
                    bytes(1184),
                    structural={"key_share_group": 0x0200},
                ),
                offered_groups=ALL_GROUPS,
            )
        )

        assert msg.key_share_entries[0][0] == 0x0200
        assert msg.supported_groups == tuple(codepoint(g) for g in ALL_GROUPS)


class TestOversizeRecord:
    """E2: record_len_override writes the override into the 2-byte length field."""

    def test_oversize_record_header_reflects_override(self):
        # RFC 8446 §5.1: TLSPlaintext.length is uint16, so the largest
        # expressible override is 65535; 65_000 is the widest oversize value
        # that still fits the field.
        buf = encode_client_hello(
            make_share(bytes(64)),
            offered_groups=ALL_GROUPS,
            record_len_override=65_000,
        )

        assert int.from_bytes(buf[3:5], "big") == 65_000
        # the fragment is not padded: declared length exceeds the real body
        assert int.from_bytes(buf[3:5], "big") > len(buf) - 5

    def test_oversize_record_is_rejected_by_parser(self):
        buf = encode_client_hello(
            make_share(bytes(64)),
            offered_groups=ALL_GROUPS,
            record_len_override=65_000,
        )

        with pytest.raises(WireParseError) as excinfo:
            parse_client_hello(buf)

        assert "65000" in str(excinfo.value)

    def test_payload_larger_than_key_share_length_field_raises(self):
        """key_exchange length is uint16; a body that cannot be encoded fails loudly."""
        with pytest.raises(CorpusError) as excinfo:
            encode_client_hello(
                make_share(bytes(70_000)), offered_groups=ALL_GROUPS
            )

        assert "65531" in str(excinfo.value)


class TestEncodeDecodeNegativeInputs:
    """Garbage in must raise a named, catchable error (E5)."""

    def test_payload_must_be_bytes(self):
        with pytest.raises(CorpusError) as excinfo:
            encode_client_hello(make_share("not-bytes"), offered_groups=ALL_GROUPS)

        assert "payload" in str(excinfo.value)

    def test_empty_offered_groups_raises(self):
        with pytest.raises(CorpusError) as excinfo:
            encode_client_hello(make_share(b"\x00"), offered_groups=())

        assert "offered_groups" in str(excinfo.value)

    def test_unknown_group_in_offered_groups_raises(self):
        with pytest.raises(CorpusError) as excinfo:
            encode_client_hello(make_share(b"\x00"), offered_groups=(513,))

        assert "513" in str(excinfo.value)

    def test_unknown_group_in_structural_override_raises(self):
        with pytest.raises(CorpusError) as excinfo:
            encode_client_hello(
                make_share(b"\x00", structural={"key_share_group": 0x9999}),
                offered_groups=ALL_GROUPS,
            )

        assert "0x9999" in str(excinfo.value) or "39321" in str(excinfo.value)


class TestParseServerHello:
    """Parser: ServerHello + HRR detection (RFC 8446 §4.1.3, §4.2)."""

    HRR_RECORD = (
        "1603010058"  # record: handshake, 0x0301, 88 bytes
        "02000054"  # handshake: server_hello, 84 bytes
        "0303"  # legacy_version
        "cf21ad74e59a6111be1d8c021e65b891"
        "c2a211167abb8c5e079e09e2c8a8339c"  # HRR magic random
        "20"  # session_id_echo length
        "00112233445566778899aabbccddeeff"
        "00112233445566778899aabbccddeeff"  # 32-byte echo
        "1301"  # cipher_suite
        "00"  # compression
        "000c"  # extensions length
        "002b00020304"  # supported_versions -> TLS 1.3
        "00330002" "11ec"  # key_share -> selected_group 0x11EC
    )

    def test_hrr_detected_and_negotiated_group_is_none(self):
        """E18: HRR sets chosen_group None; detail names HRR."""
        msg = parse_server_hello(bytes.fromhex(self.HRR_RECORD))

        assert msg.is_hrr is True
        assert msg.chosen_group is None
        assert msg.hrr_selected_group == 0x11EC
        assert msg.key_exchange == b""

    def test_hrr_random_helper(self):
        assert is_hrr_random(HRR_MAGIC_RANDOM) is True
        assert is_hrr_random(bytes(32)) is False
        assert is_hrr_random(HRR_MAGIC_RANDOM[:-1]) is False

    def test_normal_server_hello_roundtrip(self):
        msg = ServerHelloMsg(
            chosen_group=0x0201,
            key_exchange=bytes(1088),
            legacy_session_id_echo=bytes(32),
        )

        parsed = parse_server_hello(encode_server_hello(msg))

        assert parsed.chosen_group == 0x0201
        assert parsed.key_exchange == bytes(1088)
        assert parsed.legacy_session_id_echo == bytes(32)
        assert parsed.is_hrr is False

    def test_server_hello_roundtrip_is_hypothesis_stable(self):
        @given(
            group=st.sampled_from([0x0200, 0x0201, 0x0202, 0x11EB, 0x11EC, 0x11ED]),
            kex_len=st.integers(min_value=0, max_value=2048),
            sid_len=st.integers(min_value=0, max_value=32),
        )
        @settings(max_examples=200, deadline=None)
        def inner(group, kex_len, sid_len):
            payload = bytes((i * 7 + 3) % 256 for i in range(kex_len))
            sid = bytes((i * 11 + 1) % 256 for i in range(sid_len))
            parsed = parse_server_hello(
                encode_server_hello(
                    ServerHelloMsg(
                        chosen_group=group,
                        key_exchange=payload,
                        legacy_session_id_echo=sid,
                    )
                )
            )

            assert parsed.chosen_group == group
            assert parsed.key_exchange == payload
            assert parsed.legacy_session_id_echo == sid

        inner()

    def test_malformed_server_share_raises(self):
        """E8: key_share key_exchange length promises more bytes than the record holds.

        RFC 8446 §4: a handshake record's fragment starts with HandshakeType
        and a uint24 length; the ServerHello header is therefore part of the
        fixture. Only the key_exchange length field is deliberately wrong.
        """
        body = (
            "0303"
            "000102030405060708090a0b0c0d0e0f"
            "101112131415161718191a1b1c1d1e1f"
            "20"
            "00112233445566778899aabbccddeeff"
            "00112233445566778899aabbccddeeff"
            "1301"
            "00"
            "0010"  # extensions length: supported_versions (6) + key_share (4+6)
            "002b00020304"
            "00330006"  # key_share ext: type 0x0033, ext length 6
            "11ec"  # group 0x11EC
            "0460"  # key_exchange length 1120
            "0011"  # ... but only 2 bytes follow
        )
        body_bytes = bytes.fromhex(body)
        fragment = (
            bytes([SERVER_HELLO]) + len(body_bytes).to_bytes(3, "big") + body_bytes
        )
        buf = (
            bytes([HANDSHAKE_RECORD])
            + LEGACY_RECORD_VERSION.to_bytes(2, "big")
            + len(fragment).to_bytes(2, "big")
            + fragment
        )

        with pytest.raises(WireParseError) as excinfo:
            parse_server_hello(buf)

        assert "key_exchange" in str(excinfo.value) or "key_share" in str(excinfo.value)

    def test_empty_buffer_raises(self):
        with pytest.raises(WireParseError):
            parse_server_hello(b"")

    def test_short_record_header_raises(self):
        with pytest.raises(WireParseError):
            parse_server_hello(b"\x16\x03\x01")

    def test_non_tls_response_raises(self):
        """E17: HTTP response is a record-layer mismatch, never acceptance."""
        with pytest.raises(WireParseError) as excinfo:
            parse_server_hello(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")

        assert "0x48" in str(excinfo.value).lower() or "HTTP" in str(excinfo.value)

    def test_alert_record_passed_to_server_hello_parser_raises(self):
        with pytest.raises(WireParseError) as excinfo:
            parse_server_hello(encode_alert(ALERT_FATAL, ALERT_HANDSHAKE_FAILURE))

        assert "alert" in str(excinfo.value).lower()

    def test_client_hello_handshake_type_rejected(self):
        buf = encode_client_hello(make_share(b"\x00" * 8), offered_groups=ALL_GROUPS)

        with pytest.raises(WireParseError):
            parse_server_hello(buf)

    def test_record_length_longer_than_buffer_raises(self):
        """E10 wire half: declared length beyond the capture is a parse error."""
        buf = encode_client_hello(make_share(b"\x00" * 8), offered_groups=ALL_GROUPS)

        with pytest.raises(WireParseError) as excinfo:
            parse_client_hello(buf[:-3])

        assert "truncated" in str(excinfo.value).lower()


class TestAlerts:
    """Alert records: encode/decode, unknown description (E9)."""

    def test_alert_roundtrip_known_description(self):
        parsed = parse_alert(
            encode_alert(ALERT_FATAL, ALERT_ILLEGAL_PARAMETER)
        )

        assert isinstance(parsed, AlertMsg)
        assert (parsed.level, parsed.description) == (2, 47)
        assert parsed.raw_description == 47
        assert parsed.known is True

    def test_alert_record_header(self):
        buf = encode_alert(ALERT_WARNING, 0)

        assert buf[0] == ALERT_RECORD
        assert int.from_bytes(buf[1:3], "big") == LEGACY_RECORD_VERSION
        assert int.from_bytes(buf[3:5], "big") == 2
        assert len(buf) == 7

    def test_unknown_alert_description_preserved(self):
        """E9: description 0x7F is recorded verbatim, known=False (ALERT_OTHER at S6)."""
        parsed = parse_alert(encode_alert(ALERT_FATAL, 0x7F))

        assert parsed.description == 0x7F
        assert parsed.raw_description == 0x7F
        assert parsed.known is False

    def test_alert_with_wrong_length_raises(self):
        with pytest.raises(WireParseError):
            parse_alert(b"\x15\x03\x01\x00\x01\x02")

    def test_alert_with_wrong_content_type_raises(self):
        with pytest.raises(WireParseError):
            parse_alert(b"\x16\x03\x01\x00\x02\x02\x28")

    def test_alert_too_short_raises(self):
        with pytest.raises(WireParseError):
            parse_alert(b"\x15\x03")


class TestRoundTripProperties:
    """Spec §4 equivalence criterion: parse(encode(x)) == x, hypothesis >= 500 examples."""

    @given(
        group=st.sampled_from(ALL_GROUPS),
        payload=st.binary(min_size=0, max_size=4096),
        seed=st.integers(min_value=0, max_value=2**32 - 1),
        dup=st.booleans(),
        keep_share=st.booleans(),
    )
    @settings(
        max_examples=600,
        deadline=None,
        suppress_health_check=[HealthCheck.too_slow],
    )
    def test_client_hello_roundtrip(self, group, payload, seed, dup, keep_share):
        structural = {"duplicate_key_share": dup, "include_key_share": keep_share}
        msg = parse_client_hello(
            encode_client_hello(
                make_share(payload, group=group, structural=structural, seed=seed),
                offered_groups=ALL_GROUPS,
            )
        )

        assert msg.legacy_version == TLS12_VERSION
        assert msg.supported_versions == (TLS13_VERSION,)
        assert msg.supported_groups == tuple(codepoint(g) for g in ALL_GROUPS)
        assert msg.psk_key_exchange_modes == (PSK_DHE_KEY_EXCHANGE_MODE,)
        assert msg.signature_algorithms == DEFAULT_SIGNATURE_ALGORITHMS

        if keep_share:
            expected_entries = ((codepoint(group), payload),)
            if dup:
                expected_entries = expected_entries * 2
            assert msg.key_share_entries == expected_entries
        else:
            assert msg.key_share_entries == ()


class TestRegistryIntegration:
    """Every registered group survives a full emit/parse cycle (F1/F2)."""

    @pytest.mark.parametrize("group", ALL_GROUPS)
    def test_every_group_roundtrips_at_registry_length(self, group):
        spec = REGISTRY.get(group)
        payload = bytes((i * 13 + 5) % 256 for i in range(spec.client_share_len))
        msg = parse_client_hello(
            encode_client_hello(make_share(payload, group=group), offered_groups=(group,))
        )

        assert msg.supported_groups == (spec.codepoint,)
        assert msg.key_share_entries == ((spec.codepoint, payload),)
        assert len(msg.key_share_entries[0][1]) == spec.client_share_len

# ---------------------------------------------------------------------------
# S3 negative paths: the parser is hostile-input code (this package fuzzes
# other people's TLS stacks), so every structural failure must raise a
# WireParseError naming the field instead of reading out of bounds.
# ---------------------------------------------------------------------------


def _record(fragment, record_length=None, content_type=HANDSHAKE_RECORD):
    """Wrap a handshake fragment in a TLSPlaintext record header."""
    length = len(fragment) if record_length is None else record_length
    return (
        bytes([content_type])
        + LEGACY_RECORD_VERSION.to_bytes(2, "big")
        + length.to_bytes(2, "big")
        + fragment
    )


def _handshake(msg_type, body, declared_length=None):
    length = len(body) if declared_length is None else declared_length
    return bytes([msg_type]) + length.to_bytes(3, "big") + body


def _ext(ext_type, data):
    return ext_type.to_bytes(2, "big") + len(data).to_bytes(2, "big") + data


def _ch_body(extensions, session_id=b""):
    """Minimal, RFC 8446 §4.1.2-shaped ClientHello body."""
    cipher_suites = (0x1301).to_bytes(2, "big")
    return (
        TLS12_VERSION.to_bytes(2, "big")
        + bytes(range(32))
        + bytes([len(session_id)])
        + session_id
        + len(cipher_suites).to_bytes(2, "big")
        + cipher_suites
        + bytes([1, 0])
        + len(extensions).to_bytes(2, "big")
        + extensions
    )


def _sh_body(extensions, random_bytes=None):
    """Minimal ServerHello body; non-HRR random by default."""
    return (
        TLS12_VERSION.to_bytes(2, "big")
        + (random_bytes if random_bytes is not None else bytes(range(32)))
        + bytes([0])
        + (0x1301).to_bytes(2, "big")
        + bytes([0])
        + len(extensions).to_bytes(2, "big")
        + extensions
    )


class TestClientHelloParserNegative:
    """parse_client_hello must reject every structural violation loudly."""

    @pytest.mark.parametrize("cut", [0, 1, 2, 10, 33, 34, 35, 66, 67, 68, 69, 70, 71, 72, 100])
    def test_truncated_body_raises(self, cut):
        valid = encode_client_hello(make_share(b"\x01\x02"), offered_groups=ALL_GROUPS)
        body = valid[9:]

        with pytest.raises(WireParseError):
            parse_client_hello(_record(_handshake(CLIENT_HELLO, body[:cut])))

    def test_non_handshake_content_type_raises(self):
        buf = _record(_handshake(CLIENT_HELLO, _ch_body(b"")), content_type=0x17)

        with pytest.raises(WireParseError) as excinfo:
            parse_client_hello(buf)

        assert "expected handshake record" in str(excinfo.value)

    def test_record_length_below_handshake_header_raises(self):
        buf = _record(_handshake(CLIENT_HELLO, b""), record_length=3)

        with pytest.raises(WireParseError) as excinfo:
            parse_client_hello(buf)

        assert "record length field" in str(excinfo.value)

    def test_record_length_beyond_capture_raises(self):
        buf = _record(_handshake(CLIENT_HELLO, _ch_body(b"")), record_length=200)

        with pytest.raises(WireParseError) as excinfo:
            parse_client_hello(buf)

        assert "exceeds available bytes" in str(excinfo.value)

    def test_wrong_handshake_type_raises(self):
        buf = _record(_handshake(SERVER_HELLO, _ch_body(b"")))

        with pytest.raises(WireParseError) as excinfo:
            parse_client_hello(buf)

        assert "expected ClientHello" in str(excinfo.value)

    def test_handshake_length_beyond_record_raises(self):
        buf = _record(_handshake(CLIENT_HELLO, b"", declared_length=10))

        with pytest.raises(WireParseError) as excinfo:
            parse_client_hello(buf)

        assert "truncated handshake message" in str(excinfo.value)

    def test_extension_data_beyond_block_raises(self):
        exts = EXT_KEY_SHARE.to_bytes(2, "big") + (16).to_bytes(2, "big") + b"\x02\x01"
        buf = _record(_handshake(CLIENT_HELLO, _ch_body(exts)))

        with pytest.raises(WireParseError) as excinfo:
            parse_client_hello(buf)

        assert "truncated extension data" in str(excinfo.value)

    def test_supported_versions_empty_raises(self):
        buf = _record(_handshake(CLIENT_HELLO, _ch_body(_ext(EXT_SUPPORTED_VERSIONS, b""))))

        with pytest.raises(WireParseError) as excinfo:
            parse_client_hello(buf)

        assert "supported_versions too short" in str(excinfo.value)

    def test_supported_versions_length_beyond_extension_raises(self):
        exts = _ext(EXT_SUPPORTED_VERSIONS, b"\x04\x03\x04")
        buf = _record(_handshake(CLIENT_HELLO, _ch_body(exts)))

        with pytest.raises(WireParseError) as excinfo:
            parse_client_hello(buf)

        assert "truncated supported_versions" in str(excinfo.value)

    def test_supported_groups_too_short_raises(self):
        buf = _record(_handshake(CLIENT_HELLO, _ch_body(_ext(EXT_SUPPORTED_GROUPS, b"\x00"))))

        with pytest.raises(WireParseError) as excinfo:
            parse_client_hello(buf)

        assert "supported_groups too short" in str(excinfo.value)

    def test_supported_groups_length_beyond_extension_raises(self):
        exts = _ext(EXT_SUPPORTED_GROUPS, b"\x00\x06\x02\x01")
        buf = _record(_handshake(CLIENT_HELLO, _ch_body(exts)))

        with pytest.raises(WireParseError) as excinfo:
            parse_client_hello(buf)

        assert "truncated supported_groups" in str(excinfo.value)

    def test_key_share_too_short_raises(self):
        buf = _record(_handshake(CLIENT_HELLO, _ch_body(_ext(EXT_KEY_SHARE, b"\x00"))))

        with pytest.raises(WireParseError) as excinfo:
            parse_client_hello(buf)

        assert "key_share too short" in str(excinfo.value)

    def test_key_share_list_length_beyond_extension_raises(self):
        exts = _ext(EXT_KEY_SHARE, b"\x00\x06\x02\x01")
        buf = _record(_handshake(CLIENT_HELLO, _ch_body(exts)))

        with pytest.raises(WireParseError) as excinfo:
            parse_client_hello(buf)

        assert "truncated key_share" in str(excinfo.value)

    def test_key_share_entry_length_beyond_list_raises(self):
        # list length covers the 4-byte entry header; kex_len inside it does not.
        entry = (0x0201).to_bytes(2, "big") + (0x1000).to_bytes(2, "big")
        exts = _ext(EXT_KEY_SHARE, b"\x00\x04" + entry)
        buf = _record(_handshake(CLIENT_HELLO, _ch_body(exts)))

        with pytest.raises(WireParseError) as excinfo:
            parse_client_hello(buf)

        assert "truncated key_share entry" in str(excinfo.value)

    def test_signature_algorithms_too_short_raises(self):
        exts = _ext(EXT_SIGNATURE_ALGORITHMS, b"\x00")
        buf = _record(_handshake(CLIENT_HELLO, _ch_body(exts)))

        with pytest.raises(WireParseError) as excinfo:
            parse_client_hello(buf)

        assert "signature_algorithms too short" in str(excinfo.value)

    def test_signature_algorithms_length_beyond_extension_raises(self):
        exts = _ext(EXT_SIGNATURE_ALGORITHMS, b"\x00\x06\x04\x03")
        buf = _record(_handshake(CLIENT_HELLO, _ch_body(exts)))

        with pytest.raises(WireParseError) as excinfo:
            parse_client_hello(buf)

        assert "truncated signature_algorithms" in str(excinfo.value)

    def test_psk_modes_empty_raises(self):
        exts = _ext(EXT_PSK_KEY_EXCHANGE_MODES, b"")
        buf = _record(_handshake(CLIENT_HELLO, _ch_body(exts)))

        with pytest.raises(WireParseError) as excinfo:
            parse_client_hello(buf)

        assert "psk_key_exchange_modes too short" in str(excinfo.value)

    def test_psk_modes_length_beyond_extension_raises(self):
        exts = _ext(EXT_PSK_KEY_EXCHANGE_MODES, b"\x04\x01")
        buf = _record(_handshake(CLIENT_HELLO, _ch_body(exts)))

        with pytest.raises(WireParseError) as excinfo:
            parse_client_hello(buf)

        assert "truncated psk_key_exchange_modes" in str(excinfo.value)


class TestServerHelloParserNegative:
    """parse_server_hello must reject every structural violation loudly."""

    @pytest.mark.parametrize("cut", [0, 1, 2, 20, 33, 34, 35, 66, 67, 68, 69, 70, 71, 72])
    def test_truncated_body_raises(self, cut):
        valid = encode_server_hello(
            ServerHelloMsg(
                chosen_group=0x0201,
                key_exchange=bytes(8),
                legacy_session_id_echo=bytes(32),
            )
        )
        body = valid[9:]

        with pytest.raises(WireParseError):
            parse_server_hello(_record(_handshake(SERVER_HELLO, body[:cut])))

    def test_record_length_below_handshake_header_raises(self):
        buf = _record(_handshake(SERVER_HELLO, b""), record_length=3)

        with pytest.raises(WireParseError) as excinfo:
            parse_server_hello(buf)

        assert "record length field" in str(excinfo.value)

    def test_record_length_beyond_capture_raises(self):
        buf = _record(_handshake(SERVER_HELLO, _sh_body(b"")), record_length=200)

        with pytest.raises(WireParseError) as excinfo:
            parse_server_hello(buf)

        assert "exceeds available bytes" in str(excinfo.value)

    def test_wrong_handshake_type_raises(self):
        buf = _record(_handshake(CLIENT_HELLO, _sh_body(b"")))

        with pytest.raises(WireParseError) as excinfo:
            parse_server_hello(buf)

        assert "expected ServerHello" in str(excinfo.value)

    def test_handshake_length_beyond_record_raises(self):
        buf = _record(_handshake(SERVER_HELLO, b"", declared_length=10))

        with pytest.raises(WireParseError) as excinfo:
            parse_server_hello(buf)

        assert "truncated handshake message" in str(excinfo.value)

    def test_extension_data_beyond_block_raises(self):
        exts = EXT_KEY_SHARE.to_bytes(2, "big") + (16).to_bytes(2, "big") + b"\x02\x01"
        buf = _record(_handshake(SERVER_HELLO, _sh_body(exts)))

        with pytest.raises(WireParseError) as excinfo:
            parse_server_hello(buf)

        assert "truncated extension data" in str(excinfo.value)

    def test_key_share_entry_too_short_raises(self):
        exts = _ext(EXT_KEY_SHARE, b"\x02\x01\x00")
        buf = _record(_handshake(SERVER_HELLO, _sh_body(exts)))

        with pytest.raises(WireParseError) as excinfo:
            parse_server_hello(buf)

        assert "key_share entry too short" in str(excinfo.value)

    def test_supported_versions_too_short_raises(self):
        exts = _ext(EXT_SUPPORTED_VERSIONS, b"\x03")
        buf = _record(_handshake(SERVER_HELLO, _sh_body(exts)))

        with pytest.raises(WireParseError) as excinfo:
            parse_server_hello(buf)

        assert "supported_versions too short" in str(excinfo.value)

    def test_supported_versions_not_tls13_raises(self):
        exts = _ext(EXT_SUPPORTED_VERSIONS, TLS12_VERSION.to_bytes(2, "big"))
        buf = _record(_handshake(SERVER_HELLO, _sh_body(exts)))

        with pytest.raises(WireParseError) as excinfo:
            parse_server_hello(buf)

        assert "unsupported version" in str(excinfo.value)

    def test_missing_key_share_raises(self):
        exts = _ext(EXT_SUPPORTED_VERSIONS, TLS13_VERSION.to_bytes(2, "big"))
        buf = _record(_handshake(SERVER_HELLO, _sh_body(exts)))

        with pytest.raises(WireParseError) as excinfo:
            parse_server_hello(buf)

        assert "no key_share extension found" in str(excinfo.value)

    def test_hrr_key_share_too_short_raises(self):
        exts = _ext(EXT_KEY_SHARE, b"\x02")
        buf = _record(
            _handshake(SERVER_HELLO, _sh_body(exts, random_bytes=HRR_MAGIC_RANDOM))
        )

        with pytest.raises(WireParseError) as excinfo:
            parse_server_hello(buf)

        assert "key_share too short" in str(excinfo.value)

    def test_hrr_supported_versions_too_short_raises(self):
        exts = _ext(EXT_SUPPORTED_VERSIONS, b"\x03")
        buf = _record(
            _handshake(SERVER_HELLO, _sh_body(exts, random_bytes=HRR_MAGIC_RANDOM))
        )

        with pytest.raises(WireParseError) as excinfo:
            parse_server_hello(buf)

        assert "supported_versions too short" in str(excinfo.value)

    def test_hrr_supported_versions_not_tls13_raises(self):
        exts = _ext(EXT_SUPPORTED_VERSIONS, TLS12_VERSION.to_bytes(2, "big"))
        buf = _record(
            _handshake(SERVER_HELLO, _sh_body(exts, random_bytes=HRR_MAGIC_RANDOM))
        )

        with pytest.raises(WireParseError) as excinfo:
            parse_server_hello(buf)

        assert "unsupported version" in str(excinfo.value)


class TestEncoderContractViolations:
    """encode_client_hello rejects malformed inputs before emitting bytes."""

    def test_share_group_must_be_group_enum(self):
        from dataclasses import replace

        share = replace(make_share(b"\x01"), group="mlkem768")

        with pytest.raises(CorpusError) as excinfo:
            encode_client_hello(share, offered_groups=ALL_GROUPS)

        assert "share.group must be a Group enum" in str(excinfo.value)

    def test_payload_must_be_bytes(self):
        from dataclasses import replace

        share = replace(make_share(b"\x01"), payload=bytearray(b"\x01"))

        with pytest.raises(CorpusError) as excinfo:
            encode_client_hello(share, offered_groups=ALL_GROUPS)

        assert "share.payload must be bytes" in str(excinfo.value)

    def test_legacy_session_id_wrong_length_raises(self):
        with pytest.raises(CorpusError) as excinfo:
            encode_client_hello(
                make_share(b"\x01"), offered_groups=ALL_GROUPS, legacy_session_id=bytes(31)
            )

        assert "legacy_session_id must be empty or 32 bytes" in str(excinfo.value)

    def test_supported_groups_override_must_be_list(self):
        share = make_share(b"\x01", structural={"supported_groups": 5})

        with pytest.raises(CorpusError) as excinfo:
            encode_client_hello(share, offered_groups=ALL_GROUPS)

        assert "must be a list of ints" in str(excinfo.value)

    def test_supported_groups_override_rejects_non_int_entries(self):
        share = make_share(b"\x01", structural={"supported_groups": ["0x0201"]})

        with pytest.raises(CorpusError) as excinfo:
            encode_client_hello(share, offered_groups=ALL_GROUPS)

        assert "must be a list of ints" in str(excinfo.value)

    def test_key_share_group_override_must_be_int(self):
        share = make_share(b"\x01", structural={"key_share_group": "not-a-number"})

        with pytest.raises(CorpusError) as excinfo:
            encode_client_hello(share, offered_groups=ALL_GROUPS)

        assert "key_share_group must be an int" in str(excinfo.value)

    @pytest.mark.parametrize("override", [-1, 0x10000])
    def test_record_length_override_must_fit_uint16(self, override):
        with pytest.raises(CorpusError) as excinfo:
            encode_client_hello(
                make_share(b"\x01"),
                offered_groups=ALL_GROUPS,
                record_len_override=override,
            )

        assert "uint16" in str(excinfo.value)


class TestParserBoundaryDetails:
    """Remaining wire-format boundaries: record minimums, compression block,
    explicit session-id echo, HRR extension truncation, short alert."""

    def test_client_hello_shorter_than_minimum_record_raises(self):
        with pytest.raises(WireParseError) as excinfo:
            parse_client_hello(b"\x16\x03\x01\x00\x00")

        assert "shorter than minimum TLS overhead" in str(excinfo.value)

    def test_server_hello_shorter_than_minimum_record_raises(self):
        with pytest.raises(WireParseError) as excinfo:
            parse_server_hello(b"\x16\x03\x03\x00\x00")

        assert "shorter than minimum TLS overhead" in str(excinfo.value)

    @pytest.mark.parametrize("cut", [39, 40, 41])
    def test_compression_and_extensions_length_truncation_raises(self, cut):
        body = _ch_body(_ext(EXT_SUPPORTED_VERSIONS, b"\x02\x03\x04"))

        with pytest.raises(WireParseError):
            parse_client_hello(_record(_handshake(CLIENT_HELLO, body[:cut])))

    def test_explicit_32_byte_session_id_is_echoed_verbatim(self):
        sid = bytes((i * 3 + 1) % 256 for i in range(32))

        msg = parse_client_hello(
            encode_client_hello(
                make_share(b"\x01"), offered_groups=ALL_GROUPS, legacy_session_id=sid
            )
        )

        assert msg.legacy_session_id == sid

    def test_hrr_extension_data_beyond_block_raises(self):
        # HRR random selects the HRR extension walker; the trailing 2 bytes
        # promise an ext_data_len the block does not contain.
        exts = EXT_KEY_SHARE.to_bytes(2, "big") + (16).to_bytes(2, "big") + b"\x02\x01"
        buf = _record(
            _handshake(SERVER_HELLO, _sh_body(exts, random_bytes=HRR_MAGIC_RANDOM))
        )

        with pytest.raises(WireParseError) as excinfo:
            parse_server_hello(buf)

        assert "truncated extension data" in str(excinfo.value)

    def test_alert_shorter_than_two_bytes_raises(self):
        with pytest.raises(WireParseError) as excinfo:
            parse_alert(b"\x15")

        assert "buffer too short" in str(excinfo.value)
