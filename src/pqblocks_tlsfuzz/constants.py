"""Constants module for pqblocks_tlsfuzz (slice S1).

FIPS 203 Table 2/3 ML-KEM parameter dataclasses + GroupRegistry with
codepoints, share lengths, and RFC 10024 hybrid wire layouts.
"""

from dataclasses import dataclass
from enum import Enum

from pqblocks_tlsfuzz.errors import CorpusError


class Group(str, Enum):
    """TLS 1.3 key-share group identifiers (str-compatible)."""

    MLKEM512 = "mlkem512"
    MLKEM768 = "mlkem768"
    MLKEM1024 = "mlkem1024"
    X25519MLKEM768 = "x25519mlkem768"
    SECP256R1MLKEM768 = "secp256r1mlkem768"
    SECP384R1MLKEM1024 = "secp384r1mlkem1024"

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class MLKEMParams:
    """FIPS 203 §8 Tables 2–3 algorithm parameters and size constants."""

    n: int
    q: int
    k: int
    eta1: int
    eta2: int
    du: int
    dv: int
    rbg_bits: int
    ek_bytes: int
    dk_bytes: int
    ct_bytes: int
    ss_bytes: int


MLKEM512_PARAMS = MLKEMParams(
    n=256, q=3329, k=2, eta1=3, eta2=2, du=10, dv=4,
    rbg_bits=128, ek_bytes=800, dk_bytes=1632, ct_bytes=768, ss_bytes=32,
)
MLKEM768_PARAMS = MLKEMParams(
    n=256, q=3329, k=3, eta1=2, eta2=2, du=10, dv=4,
    rbg_bits=192, ek_bytes=1184, dk_bytes=2400, ct_bytes=1088, ss_bytes=32,
)
MLKEM1024_PARAMS = MLKEMParams(
    n=256, q=3329, k=4, eta1=2, eta2=2, du=11, dv=5,
    rbg_bits=256, ek_bytes=1568, dk_bytes=3168, ct_bytes=1568, ss_bytes=32,
)


@dataclass(frozen=True)
class GroupSpec:
    """Frozen dataclass representing a group's wire layout specifications."""

    group: Group
    codepoint: int
    client_share_len: int
    server_share_len: int
    mlkem_ek_len: int
    mlkem_ct_len: int
    ecdhe_point_len: int
    is_hybrid: bool
    clause: str


class GroupRegistry:
    """Registry populated from FIPS 203 + RFC 10024 + draft-ietf-tls-mlkem-11."""

    def __init__(self) -> None:
        self._registry: dict[Group, GroupSpec] = self._populate_registry()

    def _populate_registry(self) -> dict[Group, GroupSpec]:
        return {
            Group.MLKEM512: GroupSpec(
                group=Group.MLKEM512,
                codepoint=0x0200,
                client_share_len=800,
                server_share_len=768,
                mlkem_ek_len=800,
                mlkem_ct_len=768,
                ecdhe_point_len=0,
                is_hybrid=False,
                clause="draft-ietf-tls-mlkem-11 §4.2, FIPS 203 §7.2",
            ),
            Group.MLKEM768: GroupSpec(
                group=Group.MLKEM768,
                codepoint=0x0201,
                client_share_len=1184,
                server_share_len=1088,
                mlkem_ek_len=1184,
                mlkem_ct_len=1088,
                ecdhe_point_len=0,
                is_hybrid=False,
                clause="draft-ietf-tls-mlkem-11 §4.2, FIPS 203 §7.2",
            ),
            Group.MLKEM1024: GroupSpec(
                group=Group.MLKEM1024,
                codepoint=0x0202,
                client_share_len=1568,
                server_share_len=1568,
                mlkem_ek_len=1568,
                mlkem_ct_len=1568,
                ecdhe_point_len=0,
                is_hybrid=False,
                clause="draft-ietf-tls-mlkem-11 §4.2, FIPS 203 §7.2",
            ),
            Group.X25519MLKEM768: GroupSpec(
                group=Group.X25519MLKEM768,
                codepoint=0x11EC,
                client_share_len=1216,
                server_share_len=1120,
                mlkem_ek_len=1184,
                mlkem_ct_len=1088,
                ecdhe_point_len=32,
                is_hybrid=True,
                clause="RFC 10024 §4.2",
            ),
            Group.SECP256R1MLKEM768: GroupSpec(
                group=Group.SECP256R1MLKEM768,
                codepoint=0x11EB,
                client_share_len=1249,
                server_share_len=1153,
                mlkem_ek_len=1184,
                mlkem_ct_len=1088,
                ecdhe_point_len=65,
                is_hybrid=True,
                clause="RFC 10024 §4.2",
            ),
            Group.SECP384R1MLKEM1024: GroupSpec(
                group=Group.SECP384R1MLKEM1024,
                codepoint=0x11ED,
                client_share_len=1665,
                server_share_len=1665,
                mlkem_ek_len=1568,
                mlkem_ct_len=1568,
                ecdhe_point_len=97,
                is_hybrid=True,
                clause="RFC 10024 §4.2",
            ),
        }

    def get(self, group: Group | str) -> GroupSpec:
        """Return GroupSpec for ``group``. Raise CorpusError on unknown group."""
        target = group
        if isinstance(group, str):
            try:
                target = Group(group.lower())
            except ValueError:
                raise CorpusError(f"Unknown group: {group!r}") from None
        if not isinstance(target, Group) or target not in self._registry:
            raise CorpusError(f"Unknown group: {group!r}")
        return self._registry[target]

    def all(self) -> tuple[GroupSpec, ...]:
        """Return all registered GroupSpecs."""
        return tuple(self._registry.values())


# — TLS 1.3 wire-level constants (RFC 8446 / draft-ietf-tls-mlkem-11) —
#: Handshake record type
HANDSHAKE_RECORD = 0x16
#: Alert record type
ALERT_RECORD = 0x15
#: ClientHello message type
CLIENT_HELLO = 0x01
#: ServerHello message type
SERVER_HELLO = 0x02
#: Legacy record version (TLS 1.2)
LEGACY_RECORD_VERSION = 0x0301
#: TLS 1.2 version
TLS12_VERSION = 0x0303
#: TLS 1.3 version
TLS13_VERSION = 0x0304
#: PSK key exchange mode (psk_dhe_ke)
PSK_DHE_KEY_EXCHANGE_MODE = 0x00

#: Extension type: key_share
EXT_KEY_SHARE = 0x0033
#: Extension type: psk_key_exchange_modes
EXT_PSK_KEY_EXCHANGE_MODES = 0x002D
#: Extension type: signature_algorithms
EXT_SIGNATURE_ALGORITHMS = 0x000D
#: Extension type: supported_groups
EXT_SUPPORTED_GROUPS = 0x000A
#: Extension type: supported_versions
EXT_SUPPORTED_VERSIONS = 0x002B

#: Alert: warning level
ALERT_WARNING = 1
#: Alert: fatal level
ALERT_FATAL = 2
#: Alert: handshake failure
ALERT_HANDSHAKE_FAILURE = 40
#: Alert: illegal parameter
ALERT_ILLEGAL_PARAMETER = 47
#: Alert: decode error
ALERT_DECODE_ERROR = 50
#: Alert: internal error
ALERT_INTERNAL_ERROR = 80