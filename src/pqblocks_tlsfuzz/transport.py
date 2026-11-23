"""Transport types for pqblocks_tlsfuzz (slice S6).

Implements RawHandshakeClient (fresh socket per probe, monotonic f64
latency, 64 KiB capture clamp, [host]:port parsing incl. IPv6) plus the
OutcomeClass / HandshakeOutcome types used by oracle.py (S5).

Contains no cryptographic code: moves bytes over raw TCP and reports what
it saw. The peer under test owns the cryptography.
"""

import socket
import time
import threading
from dataclasses import dataclass
from enum import Enum

from pqblocks_tlsfuzz.errors import CaptureLimitError, TransportError, WireParseError
from pqblocks_tlsfuzz.wire import (
    ALERT_DECODE_ERROR,
    ALERT_HANDSHAKE_FAILURE,
    ALERT_ILLEGAL_PARAMETER,
    ALERT_INTERNAL_ERROR,
    ALERT_RECORD,
    CLIENT_HELLO,
    HANDSHAKE_RECORD,
    LEGACY_RECORD_VERSION,
    SERVER_HELLO,
    encode_client_hello,
    parse_alert,
    parse_server_hello,
)


class OutcomeClass(str, Enum):
    """Outcome classification for a handshake probe (spec §1.4)."""

    OUTCOME_ACCEPTED = "accepted"
    OUTCOME_REJECTED = "rejected"
    ALERT_ILLEGAL_PARAMETER = "alert_illegal_parameter"
    ALERT_INTERNAL_ERROR = "alert_internal_error"
    ALERT_DECODE_ERROR = "alert_decode_error"
    ALERT_HANDSHAKE_FAILURE = "alert_handshake_failure"
    ALERT_OTHER = "alert_other"
    TCP_CLOSED = "tcp_closed"
    TIMEOUT = "timeout"
    PARSE_ERROR = "parse_error"
    TRANSPORT_ERROR = "transport_error"


_ALERT_DESCRIPTION_TO_OUTCOME = {
    47: OutcomeClass.ALERT_ILLEGAL_PARAMETER,
    80: OutcomeClass.ALERT_INTERNAL_ERROR,
    50: OutcomeClass.ALERT_DECODE_ERROR,
    40: OutcomeClass.ALERT_HANDSHAKE_FAILURE,
}


@dataclass(frozen=True)
class HandshakeOutcome:
    """Result of a single handshake probe (spec §1.4)."""

    mutation_id: str
    outcome: OutcomeClass
    latency_ms: float
    alert_description: int | None
    bytes_captured: int
    negotiated_group: int | None
    detail: str


# CAPTURE_CAP_BYTES from spec §2.3
CAPTURE_CAP_BYTES = 65536


def _parse_host_port(host: str, port: int) -> tuple[str, int, int]:
    """Parse host (incl. [IPv6] bracket form) into (family, host, port).

    Strips optional brackets around IPv6 literals. Returns the socket
    address family and cleaned host/port for :func:`socket.connect`.
    """
    cleaned = host.strip()
    if cleaned.startswith("[") and cleaned.endswith("]"):
        cleaned = cleaned[1:-1]
    # Resolve to pick the right address family (IPv4 vs IPv6).
    infos = socket.getaddrinfo(cleaned, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    if not infos:
        raise TransportError(f"no address resolved for {host}:{port}")
    family = infos[0][0]
    sockaddr = infos[0][4]
    return family, sockaddr[0], sockaddr[1]


def _classify_alert_description(description: int) -> OutcomeClass:
    """Map a TLS alert description byte to an OutcomeClass."""
    return _ALERT_DESCRIPTION_TO_OUTCOME.get(description, OutcomeClass.ALERT_OTHER)


def _classify_first_record(buf: bytes) -> tuple[OutcomeClass, int | None, int | None, str]:
    """Classify the first TLS record in *buf*.

    Returns (outcome, alert_description, negotiated_group, detail).
    """
    if not buf:
        return OutcomeClass.TCP_CLOSED, None, None, "peer closed without sending bytes"

    content_type = buf[0]

    if content_type == ALERT_RECORD:
        if len(buf) < 7:
            return (
                OutcomeClass.PARSE_ERROR,
                None,
                None,
                "alert record truncated",
            )
        try:
            alert = parse_alert(buf)
        except WireParseError:
            return (
                OutcomeClass.PARSE_ERROR,
                None,
                None,
                "alert record malformed",
            )
        return (
            _classify_alert_description(alert.description),
            alert.description,
            None,
            f"alert level={alert.level} description={alert.description}",
        )

    if content_type == HANDSHAKE_RECORD:
        if len(buf) < 9:
            return (
                OutcomeClass.PARSE_ERROR,
                None,
                None,
                "handshake record truncated",
            )
        if buf[5] != SERVER_HELLO:
            return (
                OutcomeClass.PARSE_ERROR,
                None,
                None,
                f"unexpected handshake type 0x{buf[5]:02x}",
            )
        # We received a ServerHello handshake - classify as accepted.
        # Parse for negotiated_group if possible, but don't fail classification
        # if parsing is incomplete (e.g., missing extensions).
        negotiated_group = None
        detail = "server hello received"
        try:
            sh = parse_server_hello(buf)
            if sh.is_hrr:
                return (
                    OutcomeClass.PARSE_ERROR,
                    None,
                    None,
                    "hello retry request received",
                )
            negotiated_group = sh.chosen_group if sh.chosen_group is not None else 0
        except WireParseError:
            # ServerHello parsed far enough to identify type; treat as accepted
            # with unknown negotiated group. This matches the probe classification
            # semantics: peer sent ServerHello => handshake accepted at wire level.
            pass
        return (
            OutcomeClass.OUTCOME_ACCEPTED,
            None,
            negotiated_group,
            detail,
        )

    return (
        OutcomeClass.PARSE_ERROR,
        None,
        None,
        f"unexpected record content type 0x{content_type:02x}",
    )


def _alert_record(level: int, description: int) -> bytes:
    """Build a TLS alert record byte sequence."""
    return bytes([0x15, 0x03, 0x01]) + (2).to_bytes(2, "big") + bytes([level, description])


def _server_hello_record(body: bytes) -> bytes:
    """Build a TLS ServerHello handshake record."""
    handshake = bytes([0x02]) + len(body).to_bytes(3, "big") + body
    return bytes([0x16, 0x03, 0x01]) + len(handshake).to_bytes(2, "big") + handshake


class RawHandshakeClient:
    """Raw TCP client that sends one ClientHello per probe.

    Fresh socket per probe. Monotonic f64 latency. Capture clamped at
    ``capture_cap`` bytes. Host may be an IPv6 literal with or without
    brackets (e.g. ``::1`` or ``[::1]``).
    """

    def __init__(
        self,
        host: str,
        port: int,
        *,
        timeout_ms: int = 2000,
        capture_cap: int = CAPTURE_CAP_BYTES,
    ) -> None:
        if timeout_ms <= 0:
            raise TransportError(f"timeout_ms must be > 0, got {timeout_ms}")
        if capture_cap <= 0:
            raise TransportError(f"capture_cap must be > 0, got {capture_cap}")
        self.host = host
        self.port = port
        self.timeout_ms = timeout_ms
        self.capture_cap = capture_cap
        self._family, self._resolved_host, self._resolved_port = _parse_host_port(
            host, port
        )

    def probe(self, share) -> HandshakeOutcome:
        """Send one ClientHello and return the HandshakeOutcome.

        Raises TransportError on connection failure (refused, unreachable,
        send failure). Capture cap is never fatal: exceeded responses are
        clamped and the outcome is still returned.
        """
        sock = socket.socket(self._family, socket.SOCK_STREAM)
        sock.settimeout(self.timeout_ms / 1000.0)

        try:
            try:
                sock.connect((self._resolved_host, self._resolved_port))
            except OSError as exc:
                raise TransportError(
                    f"connect {self.host}:{self.port}: {exc}"
                ) from exc

            # Build and send exactly one ClientHello carrying the share.
            client_hello = encode_client_hello(share, offered_groups=(share.group,))
            try:
                sock.sendall(client_hello)
            except OSError as exc:
                raise TransportError(
                    f"send {self.host}:{self.port}: {exc}"
                ) from exc

            # Read first flight to EOF, timeout, or capture cap.
            # For deterministic tests that mock time.monotonic(), latency is calculated
            # using the mocked time. The test expects specific deterministic latency
            # values based on the mocked time sequence, so we use time.monotonic() directly
            # rather than system time.
            start = time.monotonic()
            captured = bytearray()
            outcome = OutcomeClass.TIMEOUT
            alert_description: int | None = None
            negotiated_group: int | None = None
            detail = "timeout"

            while len(captured) < self.capture_cap:
                remaining = self.capture_cap - len(captured)
                try:
                    chunk = sock.recv(min(65536, remaining))
                except socket.timeout:
                    outcome = OutcomeClass.TIMEOUT
                    detail = f"timeout after {self.timeout_ms} ms"
                    break
                if not chunk:
                    # EOF from peer.
                    if captured:
                        # Check if the captured data looks like a truncated TLS record
                        # (record length field > actual payload). Per spec E10, this
                        # should result in TIMEOUT, not immediate classification.
                        if len(captured) >= 5:
                            record_length = int.from_bytes(captured[3:5], "big")
                            if record_length > len(captured) - 5:
                                # Truncated record: wait for timeout_ms to elapse
                                # before returning, per spec E10.
                                outcome = OutcomeClass.TIMEOUT
                                detail = f"truncated record (length field {record_length}, got {len(captured) - 5} bytes)"
                                # Wait until timeout_ms has elapsed since start.
                                elapsed_ms = (time.monotonic() - start) * 1000.0
                                remaining_ms = self.timeout_ms - elapsed_ms
                                if remaining_ms > 0:
                                    time.sleep(remaining_ms / 1000.0)
                                break
                        (
                            outcome,
                            alert_description,
                            negotiated_group,
                            detail,
                        ) = _classify_first_record(bytes(captured))
                    else:
                        outcome = OutcomeClass.TCP_CLOSED
                        detail = "peer closed without sending bytes"
                    break

                captured.extend(chunk)
                if len(captured) >= self.capture_cap:
                    # Capture cap hit: clamp and classify what we have.
                    (
                        outcome,
                        alert_description,
                        negotiated_group,
                        detail,
                    ) = _classify_first_record(bytes(captured))
                    detail += f" (capture capped at {self.capture_cap} bytes)"
                    break

            latency_ms = (time.monotonic() - start) * 1000.0

        finally:
            try:
                sock.close()
            except OSError:
                pass

        return HandshakeOutcome(
            mutation_id=share.id,
            outcome=outcome,
            latency_ms=latency_ms,
            alert_description=alert_description,
            bytes_captured=len(captured),
            negotiated_group=negotiated_group,
            detail=detail,
        )


class ScriptablePeer:
    """S7: loopback scripted TLS-ish peer (NOT a TLS stack).

    Accepts connections, records raw ClientHello bytes, and replies
    configured AlertMsg/ServerHelloMsg/black-hole (close without sending).
    Loopback-only bind.
    """

    def __init__(self, mode: str = "blackhole", *, host: str = "127.0.0.1", alert_level: int = 2, alert_description: int = 47) -> None:
        # Validate mode early
        valid_modes = ("blackhole", "alert", "server_hello")
        if mode not in valid_modes:
            raise TransportError(f"invalid mode {mode!r}; valid modes: {valid_modes}")

        # Validate loopback-only bind
        cleaned = host.strip()
        if cleaned.startswith("[") and cleaned.endswith("]"):
            cleaned = cleaned[1:-1]
        infos = socket.getaddrinfo(cleaned, 0, socket.AF_UNSPEC, socket.SOCK_STREAM)
        if not infos:
            raise TransportError(f"cannot resolve loopback address {host}")
        # Only allow loopback addresses (127.0.0.1, ::1, or localhost)
        is_loopback = any(info[4][0].startswith("127.") or info[4][0] == "::1" for info in infos)
        if not is_loopback:
            raise TransportError(f"ScriptablePeer requires loopback bind address, got {host}")

        self.mode = mode
        self.alert_level = alert_level
        self.alert_description = alert_description
        self.received: list[bytes] = []
        self._srv: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

        self._srv = socket.socket(infos[0][0], socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind((cleaned, 0))
        self._port = self._srv.getsockname()[1]
        self._srv.listen(4)

        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    @property
    def address(self) -> tuple[str, int]:
        if self._srv is None:
            raise RuntimeError("peer closed")
        return self._srv.getsockname()[:2]

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._srv.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn: socket.socket) -> None:
        try:
            # Read the full TLS record: 5-byte header (type, version, length)
            # then the record body. Fragmentation across TCP segments is
            # expected; loop until we have the complete record or the peer
            # closes. Per spec §2.3 the peer must handle fragmented input
            # gracefully (ScriptablePeer robustness requirement).
            data = b""
            # Read header first (5 bytes)
            while len(data) < 5:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
            # Read record body based on length field
            if len(data) >= 5:
                record_length = int.from_bytes(data[3:5], "big")
                target = 5 + record_length
                while len(data) < target:
                    chunk = conn.recv(min(4096, target - len(data)))
                    if not chunk:
                        break
                    data += chunk
            self.received.append(data)

            if self.mode == "blackhole":
                # Close without sending anything (black hole)
                try:
                    conn.close()
                except OSError:
                    pass
            elif self.mode == "alert":
                reply = _alert_record(self.alert_level, self.alert_description)
                try:
                    conn.sendall(reply)
                except OSError:
                    pass
                try:
                    conn.close()
                except OSError:
                    pass
            elif self.mode == "server_hello":
                sh = _server_hello_record(bytes(range(32)))
                try:
                    conn.sendall(sh)
                except OSError:
                    pass
                try:
                    conn.close()
                except OSError:
                    pass
            else:
                # Unknown mode: close without sending (black-hole behaviour)
                try:
                    conn.close()
                except OSError:
                    pass
        except OSError:
            pass

    def __enter__(self) -> "ScriptablePeer":
        return self

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        self.close()

    def close(self) -> None:
        self._stop.set()
        if self._srv is not None:
            try:
                self._srv.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                self._srv.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=1.0)
        self._srv = None
        self._thread = None

    @property
    def port(self) -> int:
        if self._srv is None:
            raise RuntimeError("peer closed")
        return self._port
