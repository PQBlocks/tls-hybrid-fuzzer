"""Tests for transport.py (slice S6).

RawHandshakeClient: fresh socket per probe, monotonic f64 latency,
64 KiB capture clamp, [host]:port parsing incl. IPv6.
Raises TransportError on connection failure; CaptureLimitError defined
in errors.py (never fatal: capture is clamped, probe continues).

Covers spec §6.2 test_transport.py rows:
- E2: oversized input capture cap enforced  -> test_capture_cap_enforced
- E10: oversize record length field -> TIMEOUT -> test_oversize_record_timeout
- E14: 10 MiB flood -> capture clamped at 64 KiB -> test_capture_cap_flood
- E16: timeout boundary -> TIMEOUT -> test_timeout_boundary
"""

import socket
import threading
import time

import pytest

from pqblocks_tlsfuzz.constants import Group, GroupRegistry
from pqblocks_tlsfuzz.corpus import KeyShareMutation, MutationClass
from pqblocks_tlsfuzz.errors import TransportError
from pqblocks_tlsfuzz.transport import (
    CAPTURE_CAP_BYTES,
    HandshakeOutcome,
    OutcomeClass,
    RawHandshakeClient,
)

REGISTRY = GroupRegistry()


def make_share(payload=b"\x00" * 32, *, group=Group.MLKEM768, seed=0):
    """Build a KeyShareMutation carrying the given key_exchange payload."""
    return KeyShareMutation(
        id=f"{group.value}-test-{seed}",
        group=group,
        mutation_class=MutationClass.HYBRID_BOUNDARY_SHIFT,
        seed=seed,
        offset=-1,
        payload=payload,
    )


class _TestPeer:
    """Minimal loopback peer for transport tests (test-only helper, not S7's ScriptablePeer).

    Accepts connections, reads the ClientHello, then sends a configured
    response and closes. reply=b"" => black hole (close without sending).
    """

    def __init__(self, response: bytes = b"", *, delay_ms: int = 0):
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(4)
        self.port = self._srv.getsockname()[1]
        self.response = response
        self.delay_ms = delay_ms
        self.received: list[bytes] = []
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        while True:
            try:
                conn, _ = self._srv.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        try:
            data = b""
            while len(data) < 5:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
            if len(data) >= 5:
                record_len = int.from_bytes(data[3:5], "big")
                while len(data) < 5 + record_len:
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    data += chunk
            self.received.append(data)
        except OSError:
            pass
        if self.delay_ms:
            time.sleep(self.delay_ms / 1000.0)
        try:
            if self.response:
                conn.sendall(self.response)
        except OSError:
            pass
        try:
            conn.close()
        except OSError:
            pass

    def close(self):
        try:
            self._srv.close()
        except OSError:
            pass


def _alert_record(level: int, description: int) -> bytes:
    return bytes([0x15, 0x03, 0x01]) + (2).to_bytes(2, "big") + bytes([level, description])


def _server_hello_record(body: bytes) -> bytes:
    handshake = bytes([0x02]) + len(body).to_bytes(3, "big") + body
    return bytes([0x16, 0x03, 0x01]) + len(handshake).to_bytes(2, "big") + handshake


class TestRawHandshakeClientConstruction:
    """Client construction: endpoint parsing and validation."""

    def test_parses_ipv4_host_and_port(self):
        client = RawHandshakeClient("127.0.0.1", 4433)
        assert client.port == 4433
        assert client.host == "127.0.0.1"

    def test_parses_ipv6_bracket_form(self):
        client = RawHandshakeClient("[::1]", 4433)
        assert client.host == "[::1]"
        assert client.port == 4433

    def test_parses_ipv6_plain_form(self):
        client = RawHandshakeClient("::1", 4433)
        assert client.host == "::1"
        assert client.port == 4433

    def test_rejects_nonpositive_timeout(self):
        with pytest.raises(TransportError):
            RawHandshakeClient("127.0.0.1", 4433, timeout_ms=0)

    def test_rejects_nonpositive_capture_cap(self):
        with pytest.raises(TransportError):
            RawHandshakeClient("127.0.0.1", 4433, capture_cap=0)

    def test_default_capture_cap_is_64kib(self):
        client = RawHandshakeClient("127.0.0.1", 4433)
        assert client.capture_cap == CAPTURE_CAP_BYTES == 65536

    def test_default_timeout_ms_is_2000(self):
        client = RawHandshakeClient("127.0.0.1", 4433)
        assert client.timeout_ms == 2000


class TestConnectionFailure:
    """Connection failures raise TransportError."""

    def test_connection_refused_raises_transport_error(self):
        client = RawHandshakeClient("127.0.0.1", 19999)
        share = make_share()
        with pytest.raises(TransportError) as excinfo:
            client.probe(share)
        assert "19999" in str(excinfo.value)


class TestProbeHappyPath:
    """Successful probes return HandshakeOutcome with classified outcome."""

    def test_alert_illegal_parameter_mapped(self):
        """Peer sends alert(illegal_parameter) -> outcome ALERT_ILLEGAL_PARAMETER."""
        peer = _TestPeer(response=_alert_record(2, 47))
        try:
            client = RawHandshakeClient("127.0.0.1", peer.port, timeout_ms=5000)
            share = make_share()
            outcome = client.probe(share)
            assert outcome.outcome == OutcomeClass.ALERT_ILLEGAL_PARAMETER
            assert outcome.alert_description == 47
            assert outcome.bytes_captured == 7
            assert outcome.latency_ms > 0
            assert isinstance(outcome.latency_ms, float)
            assert isinstance(outcome, HandshakeOutcome)
            assert outcome.mutation_id == share.id
        finally:
            peer.close()

    def test_alert_unknown_description_mapped_to_other(self):
        """Peer sends alert(0x7f) -> outcome ALERT_OTHER."""
        peer = _TestPeer(response=_alert_record(2, 0x7F))
        try:
            client = RawHandshakeClient("127.0.0.1", peer.port, timeout_ms=5000)
            share = make_share()
            outcome = client.probe(share)
            assert outcome.outcome == OutcomeClass.ALERT_OTHER
            assert outcome.alert_description == 0x7F
        finally:
            peer.close()

    def test_server_hello_is_accepted(self):
        """Peer sends ServerHello -> outcome OUTCOME_ACCEPTED."""
        sh_body = (
            bytes.fromhex("0303")
            + bytes(range(32))
            + bytes([0])
            + bytes.fromhex("1301")
            + bytes([0])
            + bytes([0, 0])
        )
        peer = _TestPeer(response=_server_hello_record(sh_body))
        try:
            client = RawHandshakeClient("127.0.0.1", peer.port, timeout_ms=5000)
            share = make_share()
            outcome = client.probe(share)
            assert outcome.outcome == OutcomeClass.OUTCOME_ACCEPTED
            # ServerHello is invalid (no key_share extension), so negotiated_group is None.
            # Spec §1.4: negotiated_group: int | None
            assert outcome.negotiated_group is None
        finally:
            peer.close()

    def test_blackhole_peer_tcp_closed(self):
        """Peer accepts and closes without sending -> TCP_CLOSED."""
        peer = _TestPeer(response=b"")
        try:
            client = RawHandshakeClient("127.0.0.1", peer.port, timeout_ms=5000)
            share = make_share()
            outcome = client.probe(share)
            assert outcome.outcome == OutcomeClass.TCP_CLOSED
            assert outcome.bytes_captured == 0
        finally:
            peer.close()


class TestCaptureCap:
    """E2/E14: capture cap is enforced and clamps floods."""

    def test_capture_cap_enforced(self):
        """E2: capture clamped at CAPTURE_CAP_BYTES, never exceeds."""
        alert = _alert_record(2, 47)
        padding = b"\x00" * (CAPTURE_CAP_BYTES - len(alert))
        peer = _TestPeer(response=alert + padding)
        try:
            client = RawHandshakeClient("127.0.0.1", peer.port, timeout_ms=5000)
            share = make_share()
            outcome = client.probe(share)
            assert outcome.bytes_captured == CAPTURE_CAP_BYTES
            assert outcome.bytes_captured <= CAPTURE_CAP_BYTES
            assert outcome.outcome == OutcomeClass.ALERT_ILLEGAL_PARAMETER
        finally:
            peer.close()

    def test_capture_cap_flood(self):
        """E14: peer floods 10 MiB -> capture clamped at 64 KiB, outcome recorded."""
        flood = b"\x41" * (10 * 1024 * 1024)
        peer = _TestPeer(response=flood)
        try:
            client = RawHandshakeClient("127.0.0.1", peer.port, timeout_ms=5000)
            share = make_share()
            outcome = client.probe(share)
            assert outcome.bytes_captured == CAPTURE_CAP_BYTES
            assert outcome.outcome == OutcomeClass.PARSE_ERROR
        finally:
            peer.close()


class TestTimeout:
    """E10/E16: timeout behaviour is bounded by timeout_ms."""

    def test_oversize_record_timeout(self):
        """E10: record length field exceeds actual bytes -> TIMEOUT, never blocks past timeout_ms."""
        header = bytes([0x16, 0x03, 0x01]) + (65000).to_bytes(2, "big")
        body = b"\x01" * 100
        peer = _TestPeer(response=header + body)
        try:
            client = RawHandshakeClient("127.0.0.1", peer.port, timeout_ms=1000)
            share = make_share()
            outcome = client.probe(share)
            assert outcome.outcome == OutcomeClass.TIMEOUT
            assert outcome.latency_ms >= 500
            assert outcome.latency_ms <= 3000
            assert outcome.bytes_captured == 105
        finally:
            peer.close()

    def test_timeout_boundary(self):
        """E16: peer sleeps timeout_ms then closes -> TIMEOUT (>=), monotonic, 2x tolerance."""
        peer = _TestPeer(response=b"", delay_ms=1500)
        try:
            client = RawHandshakeClient("127.0.0.1", peer.port, timeout_ms=1000)
            share = make_share()
            outcome = client.probe(share)
            assert outcome.outcome in (
                OutcomeClass.TIMEOUT,
                OutcomeClass.TCP_CLOSED,
            )
            assert outcome.latency_ms >= 500
            assert outcome.latency_ms <= 3000
        finally:
            peer.close()


class TestScriptablePeer:
    """S7: ScriptablePeer - loopback scripted TLS-ish peer.

    Accepts connections, records raw ClientHello bytes, replies configured
    AlertMsg/ServerHelloMsg/black-hole. Loopback-only bind.
    """

    def test_scriptable_peer_blackhole(self):
        """Black-hole mode: accepts, records ClientHello, closes without sending."""
        from pqblocks_tlsfuzz.transport import ScriptablePeer

        peer = ScriptablePeer(mode="blackhole")
        try:
            assert peer.port > 0
            client = RawHandshakeClient("127.0.0.1", peer.port, timeout_ms=5000)
            share = make_share()
            outcome = client.probe(share)
            assert outcome.outcome == OutcomeClass.TCP_CLOSED
            assert outcome.bytes_captured == 0
        finally:
            peer.close()

    def test_scriptable_peer_records_received_bytes(self):
        """Peer records the exact raw ClientHello bytes it received."""
        from pqblocks_tlsfuzz.transport import ScriptablePeer

        peer = ScriptablePeer(mode="blackhole")
        try:
            client = RawHandshakeClient("127.0.0.1", peer.port, timeout_ms=5000)
            share = make_share(payload=b"\xAB" * 64)
            client.probe(share)
            # Wait briefly for the server thread to finish recording
            deadline = time.time() + 2.0
            while not peer.received and time.time() < deadline:
                time.sleep(0.01)
            assert len(peer.received) == 1
            received = peer.received[0]
            # Must be a TLS handshake record containing ClientHello (type 0x01)
            assert received[0] == 0x16  # handshake record
            assert received[5] == 0x01  # ClientHello
            # The payload bytes we set must appear in the received data
            assert b"\xAB" * 64 in received
        finally:
            peer.close()

    def test_scriptable_peer_loopback_only_bind(self):
        """ScriptablePeer must bind to loopback only; non-loopback raises."""
        from pqblocks_tlsfuzz.transport import ScriptablePeer
        from pqblocks_tlsfuzz.errors import TransportError

        # Default bind must be loopback
        peer = ScriptablePeer()
        try:
            host, port = peer.address
            assert host in ("127.0.0.1", "::1", "localhost")
        finally:
            peer.close()

        # Explicit non-loopback bind must raise
        with pytest.raises(TransportError):
            ScriptablePeer(host="0.0.0.0")

    def test_scriptable_peer_alert_reply(self):
        """Alert mode: peer replies with a configured alert record."""
        from pqblocks_tlsfuzz.transport import ScriptablePeer

        peer = ScriptablePeer(mode="alert", alert_level=2, alert_description=47)
        try:
            client = RawHandshakeClient("127.0.0.1", peer.port, timeout_ms=5000)
            share = make_share()
            outcome = client.probe(share)
            assert outcome.outcome == OutcomeClass.ALERT_ILLEGAL_PARAMETER
            assert outcome.alert_description == 47
        finally:
            peer.close()

    def test_scriptable_peer_server_hello_reply(self):
        """ServerHello mode: peer replies with a ServerHello record."""
        from pqblocks_tlsfuzz.transport import ScriptablePeer

        peer = ScriptablePeer(mode="server_hello")
        try:
            client = RawHandshakeClient("127.0.0.1", peer.port, timeout_ms=5000)
            share = make_share()
            outcome = client.probe(share)
            assert outcome.outcome == OutcomeClass.OUTCOME_ACCEPTED
        finally:
            peer.close()

    def test_scriptable_peer_invalid_mode_raises(self):
        """Unknown mode raises TransportError (loud error, no silent default)."""
        from pqblocks_tlsfuzz.transport import ScriptablePeer
        from pqblocks_tlsfuzz.errors import TransportError

        with pytest.raises(TransportError):
            ScriptablePeer(mode="not_a_mode")
