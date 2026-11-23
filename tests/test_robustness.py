import time
import socket
import struct
import pytest
from pqblocks_tlsfuzz.transport import ScriptablePeer, RawHandshakeClient
from pqblocks_tlsfuzz.corpus import KeyShareMutation, MutationClass
from pqblocks_tlsfuzz.constants import Group
from pqblocks_tlsfuzz.wire import encode_client_hello
from pqblocks_tlsfuzz.errors import TransportError

class TestScriptablePeerRobustness:
    "S7-Robustness: tests for fragmentation and prompt close."

    def test_scriptable_peer_records_full_clienthello_when_fragmented(self):
        "Peer MUST record full ClientHello bytes even if delivered in multiple fragments."
        peer = ScriptablePeer(mode="blackhole")
        try:
            host, port = peer.address
            client_sock = socket.create_connection((host, port), timeout=5)

            # 1. Construct a real handshake message
            share = KeyShareMutation(
                id="test-fragmented",
                group=Group.MLKEM512,
                mutation_class=MutationClass.VALID_CONTROL,
                seed=0,
                offset=0,
                payload=b"\x01" * 32,
            )
            client_hello = encode_client_hello(
                share,
                offered_groups=(Group.MLKEM512,),
            )

            # 2. Send in fragments: header first, then body
            # TLS Record header is 5 bytes: type (1), ver (2), len (2)
            header = client_hello[:5]
            body = client_hello[5:]

            client_sock.sendall(header)
            time.sleep(0.1)  # force fragmentation
            client_sock.sendall(body)
            client_sock.close()

            # 3. Wait for peer to process
            deadline = time.time() + 2.0
            while not peer.received and time.time() < deadline:
                time.sleep(0.01)

            assert len(peer.received) == 1, f"Expected 1 received record, got {len(peer.received)}"
            received = peer.received[0]
            assert len(received) == len(client_hello), f"Expected {len(client_hello)} bytes, got {len(received)}"
            assert received == client_hello

        finally:
            peer.close()

    def test_scriptable_peer_close_is_prompt(self):
        "Peer close() should be prompt (not block for 2.0s when no connection is pending)."
        peer = ScriptablePeer(mode="blackhole")
        start = time.time()
        peer.close()
        duration = time.time() - start

        # It should return almost immediately if the accept loop doesn't hang for the full timeout.
        # 0.5s is a safe threshold for a successful prompt close.
        assert duration < 0.5, f"close() was not prompt: took {duration:.2f}s"

    def test_scriptable_peer_address_reflects_bound_host(self):
        "address property should return the actually bound host."
        # Test binding to localhost (default)
        peer = ScriptablePeer(host="127.0.0.1")
        try:
            host, port = peer.address
            assert host == "127.0.0.1"
        finally:
            peer.close()

        # Test binding to ::1 if possible (though we may not have IPv6)
        try:
            peer_v6 = ScriptablePeer(host="::1")
            try:
                host, port = peer_v6.address
                # A dual-stack host mapping 0.0.0.0/:: may legally return the
                # IPv4-mapped form, so the bound literal need not be exactly "::1"
                # (transport.py resolves AF_UNSPEC and binds infos[0]).
                assert host in ("::1", "127.0.0.1"), f"Unexpected bound host: {host}"
            finally:
                peer_v6.close()
        except (OSError, TransportError):
            # Skip if IPv6 not available locally
            pass