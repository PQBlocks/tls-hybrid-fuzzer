"""TLS 1.3 wire-level emitter/parser for pqblocks_tlsfuzz (slice S3).

Emits and parses TLS 1.3 ClientHello/SeverHello/Alert records. No key
schedule, no AEAD, no KEM: the module moves bytes and reports what it saw.
"""

from dataclasses import dataclass
from hashlib import sha256
from typing import Tuple

from pqblocks_tlsfuzz.constants import (
    Group,
    GroupRegistry,
    GroupSpec,
)
from pqblocks_tlsfuzz.errors import CorpusError, WireParseError

# TLS 1.3 key-share group identifiers (str-compatible) - defined in test_wire.py
ALL_GROUPS = (
    Group.MLKEM512,
    Group.MLKEM768,
    Group.MLKEM1024,
    Group.X25519MLKEM768,
    Group.SECP256R1MLKEM768,
    Group.SECP384R1MLKEM1024,
)

# — wire-layer constants (RFC 8446 / RFC 9147) —
# Defined here in wire.py (slice S3) because they are TLS record/handshake
# codepoints consumed only by the emitter/parser; transcribed from RFC 8446
# §5.1/§4.1/§4.2 and asserted verbatim in tests/test_wire.py::TestConstants.
HANDSHAKE_RECORD = 0x16
ALERT_RECORD = 0x15
CLIENT_HELLO = 0x01
SERVER_HELLO = 0x02
LEGACY_RECORD_VERSION = 0x0301
TLS12_VERSION = 0x0303
TLS13_VERSION = 0x0304
EXT_SUPPORTED_GROUPS = 0x000A
EXT_SIGNATURE_ALGORITHMS = 0x000D
EXT_SUPPORTED_VERSIONS = 0x002B
EXT_PSK_KEY_EXCHANGE_MODES = 0x002D
EXT_KEY_SHARE = 0x0033
# alert descriptions (RFC 8446 §6.2)
ALERT_WARNING = 1
ALERT_FATAL = 2
ALERT_HANDSHAKE_FAILURE = 40
ALERT_ILLEGAL_PARAMETER = 47
ALERT_DECODE_ERROR = 50
ALERT_INTERNAL_ERROR = 80
# psk_key_exchange_modes (RFC 8446 §4.2.8.2)
PSK_DHE_KEY_EXCHANGE_MODE = 1

# — HRR magic random (RFC 8446 §4.1.3) —
HRR_MAGIC_RANDOM = bytes.fromhex(
    "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"
)

# — module-level registry for codepoint lookups —
_REGISTRY = GroupRegistry()


def _codepoint(group: Group) -> int:
    return _REGISTRY.get(group).codepoint


def _seed_bytes(label: str, seed: int, n: int) -> bytes:
    """Deterministic bytes derived from a seed (used for random/session_id)."""
    return sha256(f"{label}:{seed}".encode()).digest()[:n]


def is_hrr_random(buf: bytes) -> bool:
    """Return True iff *buf* equals the RFC 8446 HRR magic Random value."""
    return len(buf) == 32 and buf == HRR_MAGIC_RANDOM


# — dataclasses —
#: Emitted by :func:`parse_server_hello` / :func:`encode_server_hello`.
#: The spec §1.4 frozen dataclass; we add two extra fields with defaults so
#: that parse round-trips preserve the three core fields and HRR-detailed fields.
@dataclass(frozen=True)
class ServerHelloMsg:
    chosen_group: int
    key_exchange: bytes
    legacy_session_id_echo: bytes
    is_hrr: bool = False
    hrr_selected_group: int | None = None


#: Emitted by :func:`parse_client_hello`.
@dataclass(frozen=True)
class ClientHelloMsg:
    legacy_version: int
    legacy_session_id: bytes
    random: bytes
    extension_types: Tuple[int, ...]
    supported_versions: Tuple[int, ...]
    supported_groups: Tuple[int, ...]
    key_share_entries: Tuple[Tuple[int, bytes], ...]
    signature_algorithms: Tuple[int, ...]
    psk_key_exchange_modes: Tuple[int, ...]


#: Emitted by :func:`parse_alert`.
@dataclass(frozen=True)
class AlertMsg:
    level: int
    description: int
    raw_description: int
    known: bool = True


# — constant: default signature algorithms (used in ClientHello extensions) —
#: Chosen so that ``len >= 2`` and the same tuple is emitted/parsed unchanged.
DEFAULT_SIGNATURE_ALGORITHMS = (0x0403, 0x0804, 0x0805, 0x0806, 0x0807, 0x0401)


# — encode helpers —
def encode_alert(level: int, description: int) -> bytes:
    """Encode a TLS alert record (7 bytes: type 0x15, version 0x0301, u16 len=2,
    level, description)."""
    buf = bytes([ALERT_RECORD, 0x03, 0x01, 0x00, 0x02, level, description])
    return buf


# — encode: export all names the test imports —
def encode_client_hello(
    share,
    offered_groups: Tuple[Group, ...] = (),
    record_len_override: int | None = None,
    legacy_session_id: bytes = b"",
    legacy_version: int = TLS12_VERSION,
) -> bytes:
    """Emit a raw TLS 1.3 ClientHello record.

    Parameters
    ----------
    share : KeyShareMutation
        The key_share entry to carry. ``payload`` is the raw key_exchange
        bytes (ek for KEM, point‖ek for hybrid). ``group`` is the Group
        enum. ``structural`` may carry:
          - ``include_key_share``: bool (default True) — if False, omit the
            key_share extension entirely.
          - ``key_share_group``: int — override the key_share group
            codepoint (for wrong_group_bytes).
          - ``supported_groups``: list[int] — override the supported_groups
            list (for list_truncation).
          - ``reordered_groups``: list[Group] — use these groups in this
            order for supported_groups (for reordered_groups).
    offered_groups : tuple[Group, ...]
        Groups to list in the supported_groups extension. If empty and
        share.group is set, defaults to ``(share.group,)``.
    record_len_override : int | None
        If set, the TLS record length field is set to this value instead
        of the actual fragment length (for oversize_record).
    legacy_session_id : bytes
        32-byte legacy_session_id (default: deterministic from seed=0).
    legacy_version : int
        The legacy_version field in the ClientHello body (default 0x0303).

    Returns
    -------
    bytes
        Full TLS record: 0x16 0x0301 <u16 len> <handshake fragment>.
    """
    # --- validate group ---
    if not isinstance(share.group, Group):
        raise CorpusError("share.group must be a Group enum")

    if not isinstance(share.payload, bytes):
        raise CorpusError("share.payload must be bytes")

    if not offered_groups:
        raise CorpusError(
            "offered_groups must not be empty; pass at least one Group"
        )

    # Validate all offered groups
    registered_codepoints = {spec.codepoint for spec in _REGISTRY.all()}
    for g in offered_groups:
        if not isinstance(g, Group):
            raise CorpusError(
                f"offered_groups must contain Group enums, got {g!r}"
            )
        _REGISTRY.get(g)  # raises CorpusError on unknown

    # --- validate legacy_session_id ---
    if len(legacy_session_id) == 0:
        session_id = _seed_bytes("session_id", share.seed, 32)
    elif len(legacy_session_id) == 32:
        session_id = legacy_session_id
    else:
        raise CorpusError("legacy_session_id must be empty or 32 bytes")

    # --- deterministic random (32 bytes), reproducible per corpus seed ---
    random_bytes = _seed_bytes("client_random", share.seed, 32)

    # --- handshake header ---
    # ClientHello body starts with legacy_version (2 bytes) + random (32) + ...
    hv = legacy_version.to_bytes(2, "big")

    # cipher suites: three TLS 1.3 suites
    cipher_suites_list = b"".join(
        s.to_bytes(2, "big") for s in (0x1301, 0x1302, 0x1303)
    )
    cipher_suites = (6).to_bytes(2, "big") + cipher_suites_list  # 2+6=8 bytes

    # 2.c  compression: single byte 0x00
    compression = bytes([0x00])

    # -----------------------------------------------------------------
    # 3. build extensions (order: supported_versions, supported_groups,
    #    key_share, signature_algorithms, psk_key_exchange_modes)
    #    structural overrides come from share.structural (default {})
    # -----------------------------------------------------------------
    structural = dict(share.structural or {})

    # --- 3.1  supported_versions (always present) ---
    # RFC 8446 §4.2.1: ClientHello.supported_versions lists TLS 1.3 (0x0304)
    sv_data_payload = bytes([2]) + TLS13_VERSION.to_bytes(2, "big")  # u8 len=2 + TLS1.3
    sv_type = EXT_SUPPORTED_VERSIONS.to_bytes(2, "big")
    sv_ext = sv_type + len(sv_data_payload).to_bytes(2, "big") + sv_data_payload
    # contribution to extensions_length = 2+2+len(sv_data_payload) = 7

    # --- 3.2  supported_groups (default from offered_groups; may be overridden) ---
    if "supported_groups" in structural:
        sg_override = structural["supported_groups"]
        if not isinstance(sg_override, list) or not all(isinstance(x, int) for x in sg_override):
            raise CorpusError("supported_groups structural override must be a list of ints")
        supported_groups_codepoints = tuple(sg_override)
    else:
        supported_groups_codepoints = tuple(_codepoint(g) for g in offered_groups)

    sg_data = (
        bytes([(2 * len(supported_groups_codepoints)) >> 8, (2 * len(supported_groups_codepoints)) & 0xFF])
        + b"".join(cp.to_bytes(2, "big") for cp in supported_groups_codepoints)
    )
    sg_type = EXT_SUPPORTED_GROUPS.to_bytes(2, "big")
    groups_ext = sg_type + len(sg_data).to_bytes(2, "big") + sg_data
    # contribution = 2+2+len(sg_data) = 2+2+(2+2*N) = 6+2*N

    # --- 3.3  key_share (may be omitted via include_key_share) ---
    include_kw = structural.get("include_key_share", True)
    have_key_share = False
    ks_ext = b""
    ks_contribution = 0
    if include_kw:
        kg = _codepoint(share.group)
        if "key_share_group" in structural:
            try:
                kg = int(structural["key_share_group"])
            except (TypeError, ValueError):
                raise CorpusError("key_share_group must be an int")
            if kg not in registered_codepoints:
                raise CorpusError(
                    f"key_share_group 0x{kg:04x} ({kg}) is not a registered group"
                )
        kex_len = len(share.payload)
        # RFC 8446 §4.2.8.2: KeyShareEntry.key_exchange is opaque<1..2^16-1>,
        # so the length field is uint16. The entry overhead is 4 bytes
        # (group + key_exchange length), hence max payload 65531 bytes.
        if kex_len > 0xFFFB:  # 65531
            raise CorpusError(
                f"key_exchange payload {kex_len} exceeds max 65531 bytes "
                f"(uint16 key_exchange length field)"
            )
        # entry data: group(2) + kex_len(2) + kex
        ks_entry_data = kg.to_bytes(2, "big") + kex_len.to_bytes(2, "big") + share.payload
        # negotiation-structure mutation: duplicate the entry verbatim
        if structural.get("duplicate_key_share"):
            ks_entry_data = ks_entry_data * 2
        # ClientHello key_share extension_data: client_shares<0..2^16-1>
        key_share_length = len(ks_entry_data)
        if key_share_length > 0xFFFF:
            raise CorpusError(
                f"key_share entry list {key_share_length} exceeds uint16 max"
            )
        ks_extension_data = key_share_length.to_bytes(2, "big") + ks_entry_data
        ks_type = EXT_KEY_SHARE.to_bytes(2, "big")
        ks_ext = ks_type + len(ks_extension_data).to_bytes(2, "big") + ks_extension_data
        have_key_share = True
        ks_contribution = len(ks_ext)

    # --- 3.4  signature_algorithms (always present) ---
    # RFC 8446 §4.2.3: opaque signature_scheme_list<2..2^16-2> (u16 length)
    sa_list = b"".join(a.to_bytes(2, "big") for a in DEFAULT_SIGNATURE_ALGORITHMS)
    sa_data_payload = len(sa_list).to_bytes(2, "big") + sa_list
    sa_type = EXT_SIGNATURE_ALGORITHMS.to_bytes(2, "big")
    sa_ext = sa_type + len(sa_data_payload).to_bytes(2, "big") + sa_data_payload
    # contribution = 2+2+len(sa_data_payload) = 2+2+(2+2*6) = 16 for 6 algs

    # --- 3.5  psk_key_exchange_modes (always present) ---
    psk_data = bytes([1, PSK_DHE_KEY_EXCHANGE_MODE])  # u8 len=1 + mode byte
    psk_type = EXT_PSK_KEY_EXCHANGE_MODES.to_bytes(2, "big")
    psk_ext = psk_type + len(psk_data).to_bytes(2, "big") + psk_data
    # contribution = 2+2+2 = 6

    # -----------------------------------------------------------------
    # 4. compute total extensions_length and assemble extensions bytes
    # -----------------------------------------------------------------
    contributions = {
        "sv": len(sv_ext),  # 7
        "groups": len(groups_ext),  # 6+2*N
        "ks": ks_contribution if have_key_share else 0,
        "sa": len(sa_ext),  # 2+2+(1+2*len(DEFAULT_SIGNATURE_ALGORITHMS))
        "psk": 6,
    }
    total_extensions_length = sum(contributions.values())

    extensions_bytes = sv_ext + groups_ext
    if have_key_share:
        extensions_bytes += ks_ext
    extensions_bytes += sa_ext + psk_ext

    # -----------------------------------------------------------------
    # 5. assemble the handshake body (msg_body)
    # -----------------------------------------------------------------
    # Order per TLS 1.3 spec §4.1.2:
    #   legacy_version (2) | random (32) | session_id_len (1) | session_id (32)
    #   | cipher_suites_len (2) | cipher_suites list (6) | compression (1)
    #   | extensions_length (2) | extensions_data (total_extensions_length bytes)
    msg_body = (
        hv  # legacy_version 2
        + random_bytes  # 32
        + bytes([32]) + session_id  # session_id_len u8=32 + sid 32
        + cipher_suites  # u16 len=6 + 3 suites (6 bytes)
        + compression  # 1 byte
        + total_extensions_length.to_bytes(2, "big")  # extensions_length u16
        + extensions_bytes  # extensions_data
    )

    # -----------------------------------------------------------------
    # 6. assemble the full TLSPlaintext record
    # -----------------------------------------------------------------
    # Record: 0x16 type | 0x0301 version | uint16 record_length | handshake fragment
    # record_length = 4 + len(msg_body)  (because len(buf)-5 must equal that)
    # total record bytes = 5 (header) + 1 (hs type) + 3 (hs_len) + len(msg_body) = 9 + len(msg_body)
    # len(buf)-5 = 4 + len(msg_body) = record_length
    if record_len_override is not None:
        if not (0 <= record_len_override <= 0xFFFF):
            raise CorpusError("record_len_override must fit in uint16 (0–65535)")
        record_len = record_len_override
    else:
        record_len = 4 + len(msg_body)

    buf = (
        bytes([HANDSHAKE_RECORD])  # 0x16
        + LEGACY_RECORD_VERSION.to_bytes(2, "big")  # 0x0301
        + record_len.to_bytes(2, "big")
        + bytes([CLIENT_HELLO])  # 0x01
        + len(msg_body).to_bytes(3, "big")  # handshake length u24
        + msg_body
    )
    return buf


def encode_server_hello(msg: ServerHelloMsg) -> bytes:
    """Encode a TLS 1.3 ServerHello from a ServerHelloMsg dataclass.

    The returned buffer is a complete TLSPlaintext record (starts with 0x16).
    """
    # -- build handshake body --
    # layout: legacy_version(2) | random(32) | session_id_len(1) | session_id
    #         | cipher_suites_len(2)+list(6) | compression(1)
    #         | extensions_length(2)+extensions_data
    # Use deterministic random that cannot accidentally equal HRR_MAGIC_RANDOM:
    # we derive from chosen_group+key_exchange to avoid collision.

    # Derive random deterministically from payload to avoid HRR magic
    import hashlib
    rand_source = hashlib.sha256(
        f"server.hello:{msg.chosen_group}:{msg.key_exchange.hex()}".encode()
    ).digest()[:32]
    # Ensure it's not the HRR magic (extremely unlikely but guard)
    if rand_source == HRR_MAGIC_RANDOM:
        rand_source = b"\x00" * 32

    sid = msg.legacy_session_id_echo

    # RFC 8446 §4.1.3: ServerHello carries a single CipherSuite (no u16 list
    # length prefix, unlike ClientHello.cipher_suites).
    cipher_suites = (0x1301).to_bytes(2, "big")

    compression = bytes([0x00])

    # RFC 8446 §4.2.1: in ServerHello, supported_versions carries the bare
    # SelectedVersion (2 bytes) - no u8 list length as in ClientHello.
    sv_data = TLS13_VERSION.to_bytes(2, "big")
    sv_type = EXT_SUPPORTED_VERSIONS.to_bytes(2, "big")
    sv_ext = sv_type + len(sv_data).to_bytes(2, "big") + sv_data

    # key_share ext: single entry with chosen_group + key_exchange
    kg = msg.chosen_group
    kex = msg.key_exchange
    kex_len = len(kex)
    ks_entry_data = kg.to_bytes(2, "big") + kex_len.to_bytes(2, "big") + kex
    ks_data_len = len(ks_entry_data)
    ks_type = EXT_KEY_SHARE.to_bytes(2, "big")
    ks_ext = ks_type + ks_data_len.to_bytes(2, "big") + ks_entry_data

    # signature_algorithms ext
    # RFC 8446 §4.2.3: opaque signature_scheme_list<2..2^16-2> (u16 length)
    sa_list = b"".join(a.to_bytes(2, "big") for a in DEFAULT_SIGNATURE_ALGORITHMS)
    sa_data_payload = len(sa_list).to_bytes(2, "big") + sa_list
    sa_type = EXT_SIGNATURE_ALGORITHMS.to_bytes(2, "big")
    sa_ext = sa_type + len(sa_data_payload).to_bytes(2, "big") + sa_data_payload

    # psk_key_exchange_modes ext
    psk_data = bytes([1, PSK_DHE_KEY_EXCHANGE_MODE])
    psk_type = EXT_PSK_KEY_EXCHANGE_MODES.to_bytes(2, "big")
    psk_ext = psk_type + len(psk_data).to_bytes(2, "big") + psk_data

    # total extensions length
    total_ext_len = len(sv_ext) + len(ks_ext) + len(sa_ext) + len(psk_ext)

    # handshake body
    hs_body = (
        # RFC 8446 §4.1.3: ServerHello.legacy_version MUST be 0x0303.
        TLS12_VERSION.to_bytes(2, "big")
        + rand_source  # 32
        + bytes([len(sid)]) + sid  # session_id_len + echo
        + cipher_suites
        + compression
        + total_ext_len.to_bytes(2, "big")
        + sv_ext
        + ks_ext
        + sa_ext
        + psk_ext
    )

    # record layer
    record_len = 4 + len(hs_body)  # handshake header (4) + body
    return (
        bytes([HANDSHAKE_RECORD, 0x03, 0x01])
        + record_len.to_bytes(2, "big")
        + bytes([SERVER_HELLO])
        + len(hs_body).to_bytes(3, "big")
        + hs_body
    )


# =====================================================================
# Parser
# =====================================================================
#: TLS record header is 5 bytes: type(1) | version(2) | length(2).
HANDSHAKE_RECORD_HEADER_LEN = 5
#: TLS handshake header is 4 bytes: type(1) | length(3).
HANDSHAKE_HEADER_LEN = 4

#: Known alert descriptions (RFC 8446 §6.2). Maps description byte → AlertMsg.
_KNOWN_ALERTS = {
    0: "close_notify",
    10: "unexpected_message",
    20: "bad_record_mac",
    21: "decryption_failed",
    22: "record_overflow",
    30: "decompression_failure",
    40: "handshake_failure",
    41: "no_certificate",
    42: "bad_certificate",
    43: "unsupported_certificate",
    44: "certificate_revoked",
    45: "certificate_expired",
    45: "certificate_unknown",
    46: "illegal_parameter",
    47: "illegal_parameter",
    48: "unknown_ca",
    49: "access_denied",
    50: "decode_error",
    51: "decrypt_error",
    60: "export_restriction",
    70: "protocol_version",
    71: "insufficient_security",
    80: "internal_error",
    86: "inappropriate_fallback",
    90: "user_canceled",
    100: "no_renegotiation",
    109: "missing_extension",
    110: "unsupported_extension",
    111: "certificate_unobtainable",
    112: "unrecognized_name",
    113: "bad_certificate_status_response",
    114: "bad_certificate_hash_value",
    115: "unknown_psk_identity",
    116: "certificate_required",
    120: "no_application_protocol",
}


def parse_server_hello(buf: bytes) -> ServerHelloMsg:
    """Parse a TLS 1.3 ServerHello record.

    Parameters
    ----------
    buf : bytes
        Full TLS record (starting with 0x16). Must contain a complete
        ServerHello handshake message.

    Returns
    -------
    ServerHelloMsg

    Raises
    ------
    WireParseError
        On any structural violation (truncated, wrong type, malformed
        extensions, etc.).
    """
    if not buf:
        raise WireParseError("ServerHello: empty record")

    content_type = buf[0]
    # RFC 8446 §6: an alert is a distinct record type; report it as such
    # instead of blaming a short handshake record for a 2-byte alert body.
    if content_type == ALERT_RECORD:
        raise WireParseError(
            "ServerHello: got TLS alert record (0x15) instead of ServerHello"
        )

    if len(buf) < HANDSHAKE_RECORD_HEADER_LEN + HANDSHAKE_HEADER_LEN:
        raise WireParseError("ServerHello: record shorter than minimum TLS overhead")

    # --- record layer ---
    if content_type != HANDSHAKE_RECORD:
        raise WireParseError(
            f"ServerHello: expected handshake record (0x{HANDSHAKE_RECORD:02x}), "
            f"got 0x{content_type:02x}"
        )
    record_version = int.from_bytes(buf[1:3], "big")
    record_length = int.from_bytes(buf[3:5], "big")

    if record_length < 4:
        raise WireParseError("ServerHello: record length field < handshake header size")

    if record_length > len(buf) - HANDSHAKE_RECORD_HEADER_LEN:
        raise WireParseError("ServerHello: record length exceeds available bytes")

    # handshake header
    hs_msg_type = buf[5]
    if hs_msg_type != SERVER_HELLO:
        raise WireParseError(
            f"ServerHello: expected ServerHello (0x{SERVER_HELLO:02x}), "
            f"got 0x{hs_msg_type:02x}"
        )
    hs_length = int.from_bytes(buf[6:9], "big")

    hs_frg = buf[9 : 9 + hs_length]
    if len(hs_frg) < hs_length:
        raise WireParseError("ServerHello: truncated handshake message")

    # --- handshake body ---
    pos = 0
    # legacy_version (2)
    if pos + 2 > len(hs_frg):
        raise WireParseError("ServerHello: truncated legacy_version")
    legacy_version = int.from_bytes(hs_frg[pos : pos + 2], "big")
    pos += 2

    # random (32)
    if pos + 32 > len(hs_frg):
        raise WireParseError("ServerHello: truncated random")
    random_bytes = hs_frg[pos : pos + 32]
    pos += 32
    is_hrr = is_hrr_random(random_bytes)

    # session_id_echo
    if pos + 1 > len(hs_frg):
        raise WireParseError("ServerHello: truncated session_id")
    sid_len = hs_frg[pos]
    pos += 1
    if pos + sid_len > len(hs_frg):
        raise WireParseError("ServerHello: truncated session_id")
    sid_echo = bytes(hs_frg[pos : pos + sid_len])
    pos += sid_len

    # cipher_suite (2)
    if pos + 2 > len(hs_frg):
        raise WireParseError("ServerHello: truncated cipher_suite")
    pos += 2

    # compression_method (1)
    if pos + 1 > len(hs_frg):
        raise WireParseError("ServerHello: truncated compression_method")
    pos += 1

    # extensions
    if pos + 2 > len(hs_frg):
        raise WireParseError("ServerHello: truncated extensions_length")
    extensions_length = int.from_bytes(hs_frg[pos : pos + 2], "big")
    pos += 2
    if pos + extensions_length > len(hs_frg):
        raise WireParseError("ServerHello: truncated extensions_data")

    extensions_data = hs_frg[pos : pos + extensions_length]
    pos += extensions_length

    # --- parse extensions ---
    # We extract: supported_versions, key_share, and detect HRR
    ext_pos = 0
    negotiated_group = None
    key_exchange = b""

    # For HRR: the key_share extension contains only the selected_group
    # (no key_exchange bytes).
    hrr_selected_group = None
    if is_hrr:
        # HRR: look for key_share extension with just the selected_group
        while ext_pos + 4 <= len(extensions_data):
            ext_type = int.from_bytes(extensions_data[ext_pos : ext_pos + 2], "big")
            ext_data_len = int.from_bytes(extensions_data[ext_pos + 2 : ext_pos + 4], "big")
            ext_pos += 4
            if ext_pos + ext_data_len > len(extensions_data):
                raise WireParseError("ServerHello: truncated extension data")
            ext_data = extensions_data[ext_pos : ext_pos + ext_data_len]
            ext_pos += ext_data_len

            if ext_type == EXT_KEY_SHARE:
                if ext_data_len < 2:
                    raise WireParseError("ServerHello HRR: key_share too short")
                hrr_selected_group = int.from_bytes(ext_data[0:2], "big")
            elif ext_type == EXT_SUPPORTED_VERSIONS:
                if ext_data_len < 2:
                    raise WireParseError("ServerHello: supported_versions too short")
                # In HRR, supported_versions contains the selected version
                # (2 bytes, e.g. 0x0304)
                selected_version = int.from_bytes(ext_data[0:2], "big")
                # For HRR, this must be TLS 1.3
                if selected_version != TLS13_VERSION:
                    raise WireParseError(
                        f"ServerHello HRR: unsupported version 0x{selected_version:04x}"
                    )
    else:
        # Normal ServerHello: parse key_share for chosen_group + key_exchange
        while ext_pos + 4 <= len(extensions_data):
            ext_type = int.from_bytes(extensions_data[ext_pos : ext_pos + 2], "big")
            ext_data_len = int.from_bytes(extensions_data[ext_pos + 2 : ext_pos + 4], "big")
            ext_pos += 4
            if ext_pos + ext_data_len > len(extensions_data):
                raise WireParseError("ServerHello: truncated extension data")
            ext_data = extensions_data[ext_pos : ext_pos + ext_data_len]
            ext_pos += ext_data_len

            if ext_type == EXT_KEY_SHARE:
                if ext_data_len < 4:
                    raise WireParseError(
                        f"ServerHello: key_share entry too short ({ext_data_len} bytes)"
                    )
                negotiated_group = int.from_bytes(ext_data[0:2], "big")
                kex_len = int.from_bytes(ext_data[2:4], "big")
                if 4 + kex_len > ext_data_len:
                    raise WireParseError("ServerHello: key_exchange truncated")
                key_exchange = bytes(ext_data[4 : 4 + kex_len])
            elif ext_type == EXT_SUPPORTED_VERSIONS:
                if ext_data_len < 2:
                    raise WireParseError("ServerHello: supported_versions too short")
                selected_version = int.from_bytes(ext_data[0:2], "big")
                # Must be TLS 1.3
                if selected_version != TLS13_VERSION:
                    raise WireParseError(
                        f"ServerHello: unsupported version 0x{selected_version:04x}"
                    )

    if negotiated_group is None and not is_hrr:
        raise WireParseError("ServerHello: no key_share extension found")

    return ServerHelloMsg(
        chosen_group=None if is_hrr else (negotiated_group or 0),
        key_exchange=key_exchange,
        legacy_session_id_echo=sid_echo,
        is_hrr=is_hrr,
        hrr_selected_group=hrr_selected_group,
    )


def parse_client_hello(buf: bytes):
    """Parse a full TLS 1.3 ClientHello record (starting with 0x16).

    *buf* is the complete TLSPlaintext record: record header (5 bytes) +
    handshake message. Round-trip tests pass the output of
    :func:`encode_client_hello` directly.
    """
    if len(buf) < HANDSHAKE_RECORD_HEADER_LEN + HANDSHAKE_HEADER_LEN:
        raise WireParseError("ClientHello: record shorter than minimum TLS overhead")

    content_type = buf[0]
    if content_type != HANDSHAKE_RECORD:
        raise WireParseError(
            f"ClientHello: expected handshake record (0x{HANDSHAKE_RECORD:02x}), "
            f"got 0x{content_type:02x}"
        )
    record_version = int.from_bytes(buf[1:3], "big")
    record_length = int.from_bytes(buf[3:5], "big")

    if record_length < 4:
        raise WireParseError("ClientHello: record length field < handshake header size")

    if record_length > len(buf) - HANDSHAKE_RECORD_HEADER_LEN:
        raise WireParseError(
            f"ClientHello: record length {record_length} exceeds available bytes "
            f"(truncated capture)"
        )

    hs_msg_type = buf[5]
    if hs_msg_type != CLIENT_HELLO:
        raise WireParseError(
            f"ClientHello: expected ClientHello (0x{CLIENT_HELLO:02x}), "
            f"got 0x{hs_msg_type:02x}"
        )
    hs_length = int.from_bytes(buf[6:9], "big")
    if 9 + hs_length > len(buf):
        raise WireParseError("ClientHello: truncated handshake message")
    hs_frg = buf[9 : 9 + hs_length]

    pos = 0
    # legacy_version (2)
    if pos + 2 > len(hs_frg):
        raise WireParseError("ClientHello: truncated legacy_version")
    legacy_version = int.from_bytes(hs_frg[pos : pos + 2], "big")
    pos += 2

    # random (32)
    if pos + 32 > len(hs_frg):
        raise WireParseError("ClientHello: truncated random")
    random_bytes = hs_frg[pos : pos + 32]
    pos += 32

    # session_id
    if pos + 1 > len(hs_frg):
        raise WireParseError("ClientHello: truncated session_id_len")
    sid_len = hs_frg[pos]
    pos += 1
    if pos + sid_len > len(hs_frg):
        raise WireParseError("ClientHello: truncated session_id")
    legacy_session_id = bytes(hs_frg[pos : pos + sid_len])
    pos += sid_len

    # cipher_suites
    if pos + 2 > len(hs_frg):
        raise WireParseError("ClientHello: truncated cipher_suites_length")
    cs_len = int.from_bytes(hs_frg[pos : pos + 2], "big")
    pos += 2
    if pos + cs_len > len(hs_frg):
        raise WireParseError("ClientHello: truncated cipher_suites")
    pos += cs_len

    # compression_methods
    if pos + 1 > len(hs_frg):
        raise WireParseError("ClientHello: truncated compression_methods_length")
    comp_len = hs_frg[pos]
    pos += 1
    if pos + comp_len > len(hs_frg):
        raise WireParseError("ClientHello: truncated compression_methods")
    pos += comp_len

    # extensions
    if pos + 2 > len(hs_frg):
        raise WireParseError("ClientHello: truncated extensions_length")
    extensions_length = int.from_bytes(hs_frg[pos : pos + 2], "big")
    pos += 2
    if pos + extensions_length > len(hs_frg):
        raise WireParseError("ClientHello: truncated extensions")
    extensions_data = hs_frg[pos : pos + extensions_length]
    pos += extensions_length

    # --- parse extensions ---
    ext_pos = 0
    extension_types = []
    supported_versions = []
    supported_groups = []
    key_share_entries = []
    signature_algorithms = []
    psk_key_exchange_modes = []

    while ext_pos + 4 <= len(extensions_data):
        ext_type = int.from_bytes(extensions_data[ext_pos : ext_pos + 2], "big")
        ext_data_len = int.from_bytes(extensions_data[ext_pos + 2 : ext_pos + 4], "big")
        ext_pos += 4
        if ext_pos + ext_data_len > len(extensions_data):
            raise WireParseError("ClientHello: truncated extension data")
        ext_data = extensions_data[ext_pos : ext_pos + ext_data_len]
        ext_pos += ext_data_len

        extension_types.append(ext_type)
        if ext_type == EXT_SUPPORTED_VERSIONS:
            # u8 length + versions
            if ext_data_len < 1:
                raise WireParseError("ClientHello: supported_versions too short")
            sv_len = ext_data[0]
            if 1 + sv_len > ext_data_len:
                raise WireParseError("ClientHello: truncated supported_versions")
            for i in range(1, 1 + sv_len, 2):
                if i + 2 <= 1 + sv_len:
                    v = int.from_bytes(ext_data[i : i + 2], "big")
                    supported_versions.append(v)
        elif ext_type == EXT_SUPPORTED_GROUPS:
            if ext_data_len < 2:
                raise WireParseError("ClientHello: supported_groups too short")
            sg_len = int.from_bytes(ext_data[0:2], "big")
            if 2 + sg_len > ext_data_len:
                raise WireParseError("ClientHello: truncated supported_groups")
            for i in range(2, 2 + sg_len, 2):
                if i + 2 <= 2 + sg_len:
                    g = int.from_bytes(ext_data[i : i + 2], "big")
                    supported_groups.append(g)
        elif ext_type == EXT_KEY_SHARE:
            # ClientHello key_share: u16 length + entries
            if ext_data_len < 2:
                raise WireParseError("ClientHello: key_share too short")
            ks_len = int.from_bytes(ext_data[0:2], "big")
            if 2 + ks_len > ext_data_len:
                raise WireParseError("ClientHello: truncated key_share")
            iks = 2
            while iks + 4 <= 2 + ks_len:
                g = int.from_bytes(ext_data[iks : iks + 2], "big")
                kl = int.from_bytes(ext_data[iks + 2 : iks + 4], "big")
                iks += 4
                if iks + kl > 2 + ks_len:
                    raise WireParseError("ClientHello: truncated key_share entry")
                k = bytes(ext_data[iks : iks + kl])
                iks += kl
                key_share_entries.append((g, k))
        elif ext_type == EXT_SIGNATURE_ALGORITHMS:
            if ext_data_len < 2:
                raise WireParseError("ClientHello: signature_algorithms too short")
            sa_len = int.from_bytes(ext_data[0:2], "big")
            if 2 + sa_len > ext_data_len:
                raise WireParseError("ClientHello: truncated signature_algorithms")
            for i in range(2, 2 + sa_len, 2):
                if i + 2 <= 2 + sa_len:
                    a = int.from_bytes(ext_data[i : i + 2], "big")
                    signature_algorithms.append(a)
        elif ext_type == EXT_PSK_KEY_EXCHANGE_MODES:
            if ext_data_len < 1:
                raise WireParseError("ClientHello: psk_key_exchange_modes too short")
            psk_len = ext_data[0]
            if 1 + psk_len > ext_data_len:
                raise WireParseError("ClientHello: truncated psk_key_exchange_modes")
            for i in range(1, 1 + psk_len):
                psk_key_exchange_modes.append(ext_data[i])

    return ClientHelloMsg(
        legacy_version=legacy_version,
        legacy_session_id=legacy_session_id,
        random=random_bytes,
        extension_types=tuple(extension_types),
        supported_versions=tuple(supported_versions),
        supported_groups=tuple(supported_groups),
        key_share_entries=tuple(key_share_entries),
        signature_algorithms=tuple(signature_algorithms),
        psk_key_exchange_modes=tuple(psk_key_exchange_modes),
    )


def parse_alert(buf: bytes) -> AlertMsg:
    """Parse a TLS alert record.

    Parameters
    ----------
    buf : bytes
        Full TLS record (starting with 0x15).

    Returns
    -------
    AlertMsg
    """
    if len(buf) < 2:
        raise WireParseError("Alert: buffer too short")

    content_type = buf[0]
    if content_type != ALERT_RECORD:
        raise WireParseError(
            f"Alert: expected alert record (0x{ALERT_RECORD:02x}), "
            f"got 0x{content_type:02x}"
        )

    # For simplicity, just extract level + description from the last two bytes
    # (assuming the record is well-formed; transport layer handles truncation)
    if len(buf) < 7:
        raise WireParseError("Alert: record too short for alert payload")

    level = buf[5]
    description = buf[6]

    known = description in _KNOWN_ALERTS

    return AlertMsg(
        level=level,
        description=description,
        raw_description=description,
        known=known,
    )