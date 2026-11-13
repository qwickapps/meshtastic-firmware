"""Host-side tests for the QMA1 handshake. Run: python3 -m pytest tools/test_qwickmesh_tcp_auth.py

The known-answer vectors are shared with test/test_tcp_auth/TcpAuthTest.cpp (firmware side), so a change to either
implementation that breaks wire compatibility fails both suites.
"""
import hashlib
import hmac
import os
import socket
import stat
import threading

import pytest

import qwickmesh_tcp_auth as qa

SECRET = bytes(range(32))
SNONCE = bytes(range(0x10, 0x20))
CNONCE = bytes(range(0x20, 0x30))
KAT_CLIENT = "694fbbb86b5aed86ad4bc46cd0cdd13e6209c5d5d8739d7245b0ee62e672bfc6"
KAT_SERVER = "92605b0a8ba4629d4d0540bdc7a4eada4242d16c1c6d4b6897eabb629d64f53a"


def test_known_answer_vectors():
    assert qa.client_proof(SECRET, SNONCE, CNONCE).hex() == KAT_CLIENT
    assert qa.server_proof(SECRET, SNONCE, CNONCE).hex() == KAT_SERVER


def test_proofs_are_domain_separated_and_bound_to_both_nonces():
    c = qa.client_proof(SECRET, SNONCE, CNONCE)
    assert c != qa.server_proof(SECRET, SNONCE, CNONCE)
    assert c != qa.client_proof(SECRET, CNONCE, SNONCE)  # nonce order matters
    assert c != qa.client_proof(SECRET, SNONCE, bytes(16))
    assert c != qa.client_proof(bytes(32), SNONCE, CNONCE)
    # a reflected client proof must not verify as a server proof
    assert qa.server_proof(SECRET, SNONCE, CNONCE) != c


def test_matches_reference_hmac():
    ref = hmac.new(SECRET, b"QMA1-C" + SNONCE + CNONCE, hashlib.sha256).digest()
    assert qa.client_proof(SECRET, SNONCE, CNONCE) == ref


@pytest.mark.parametrize("bad", [b"", b"x" * 31, b"x" * 33, "a" * 32, None])
def test_secret_length_enforced(bad):
    with pytest.raises(ValueError):
        qa.client_proof(bad, SNONCE, CNONCE)


def test_parse_secret_hex():
    assert qa.parse_secret_hex(SECRET.hex() + "\n") == SECRET
    with pytest.raises(ValueError):
        qa.parse_secret_hex("abcd")


def test_load_secret_refuses_loose_permissions(tmp_path):
    p = tmp_path / "k"
    p.write_text(SECRET.hex())
    os.chmod(p, 0o644)
    with pytest.raises(PermissionError):
        qa.load_secret(str(p))
    os.chmod(p, stat.S_IRUSR | stat.S_IWUSR)
    assert qa.load_secret(str(p)) == SECRET


class FakeServer(threading.Thread):
    """A reference implementation of the device side, used to drive the client."""

    def __init__(self, secret, snonce=SNONCE, magic=b"QMA1", lie_server_proof=False):
        super().__init__(daemon=True)
        self.secret, self.snonce, self.magic, self.lie = secret, snonce, magic, lie_server_proof
        self.lsock = socket.socket()
        self.lsock.bind(("127.0.0.1", 0))
        self.lsock.listen(1)
        self.port = self.lsock.getsockname()[1]
        self.result = None
        self.after = b""
        self.start()

    def run(self):
        try:
            self._serve()
        except OSError:
            pass

    def _serve(self):
        conn, _ = self.lsock.accept()
        with conn:
            conn.sendall(self.magic + self.snonce)
            resp = b""
            while len(resp) < 48:
                chunk = conn.recv(48 - len(resp))
                if not chunk:
                    self.result = "closed"
                    return
                resp += chunk
            cnonce, mac = resp[:16], resp[16:]
            if hmac.compare_digest(mac, qa.client_proof(self.secret, self.snonce, cnonce)):
                self.result = "ok"
                proof = qa.server_proof(self.secret, self.snonce, cnonce)
                if self.lie:
                    proof = bytes(32)
                conn.sendall(proof)
                conn.sendall(b"\x94\xc3\x00\x00")  # first framed (empty) packet follows the handshake
                self.after = conn.recv(16)
            else:
                self.result = "bad-proof"  # real device closes without replying


def test_handshake_success_leaves_clean_stream():
    srv = FakeServer(SECRET)
    sock = qa.connect("127.0.0.1", SECRET, port=srv.port, timeout=5)
    try:
        assert sock.recv(4) == b"\x94\xc3\x00\x00"  # nothing handshake-related left in the stream
        sock.sendall(b"ping")
    finally:
        sock.close()
    srv.join(5)
    assert srv.result == "ok" and srv.after == b"ping"


def test_wrong_secret_is_rejected_and_connection_closed():
    srv = FakeServer(SECRET)
    with pytest.raises(qa.AuthError):
        qa.connect("127.0.0.1", bytes([1]) * 32, port=srv.port, timeout=5)
    srv.join(5)
    assert srv.result == "bad-proof"


def test_rogue_server_without_secret_is_detected():
    srv = FakeServer(SECRET, lie_server_proof=True)
    with pytest.raises(qa.AuthError, match="server proof mismatch"):
        qa.connect("127.0.0.1", SECRET, port=srv.port, timeout=5)


def test_bad_magic_rejected_before_any_secret_use():
    srv = FakeServer(SECRET, magic=b"HTTP")
    with pytest.raises(qa.AuthError, match="bad magic"):
        qa.connect("127.0.0.1", SECRET, port=srv.port, timeout=5)


def test_replayed_response_does_not_verify_against_fresh_nonce():
    # attacker records (cnonce, mac) from one session and replays it against a new server nonce
    cnonce = CNONCE
    mac = qa.client_proof(SECRET, SNONCE, cnonce)
    fresh = bytes(range(0x40, 0x50))
    assert not hmac.compare_digest(mac, qa.client_proof(SECRET, fresh, cnonce))


def test_client_nonces_are_random():
    seen = set()

    class Sock:
        def __init__(self):
            self.sent = b""
            self.rx = b"QMA1" + SNONCE

        def recv(self, n):
            out, self.rx = self.rx[:n], self.rx[n:]
            return out

        def sendall(self, b):
            self.sent = b

    for _ in range(8):
        s = Sock()
        with pytest.raises(qa.AuthError):  # no server proof queued -> closed
            qa.handshake(s, SECRET)
        seen.add(s.sent[:16])
    assert len(seen) == 8


def test_cli_gen_secret_does_not_print_secret(tmp_path, capsys):
    out = tmp_path / "gen.key"
    qa.main(["gen-secret", "--out", str(out)])
    text = out.read_text().strip()
    assert len(bytes.fromhex(text)) == 32
    assert text not in capsys.readouterr().out
    assert stat.S_IMODE(os.stat(out).st_mode) == 0o600
