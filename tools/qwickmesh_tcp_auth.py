#!/usr/bin/env python3
"""QwickMesh authenticated TCP API client helper (protocol "QMA1").

Performs the challenge-response handshake described in DESIGN-wifi-auth.md and then hands back a
plain connected socket (or a meshtastic StreamInterface) that carries the normal 0x94C3-framed
ToRadio/FromRadio traffic.

    S -> C : "QMA1" || snonce[16]
    C -> S : cnonce[16] || HMAC-SHA256(K, "QMA1-C" || snonce || cnonce)
    S -> C : HMAC-SHA256(K, "QMA1-S" || cnonce || snonce)       (client MUST verify: mutual auth)

Usage:
    import qwickmesh_tcp_auth as qa
    sock = qa.connect("192.168.1.50", secret=qa.load_secret("~/.qwickmesh/mesh.key"))
    iface = qa.AuthenticatedTCPInterface("192.168.1.50", secret=...)   # needs the `meshtastic` package

    python3 qwickmesh_tcp_auth.py gen-secret --out mesh.key
    python3 qwickmesh_tcp_auth.py provision --port <serial port> --secret-file mesh.key
"""
import argparse
import hashlib
import hmac
import os
import socket
import stat
import sys

MAGIC = b"QMA1"
SECRET_LEN = 32
NONCE_LEN = 16
MAC_LEN = 32
HELLO_LEN = len(MAGIC) + NONCE_LEN
DEFAULT_PORT = 4403
LABEL_C = b"QMA1-C"
LABEL_S = b"QMA1-S"


class AuthError(Exception):
    """Handshake failed (wrong secret, bad peer, protocol error)."""


def _check_secret(secret: bytes) -> None:
    if not isinstance(secret, (bytes, bytearray)) or len(secret) != SECRET_LEN:
        raise ValueError("secret must be exactly %d bytes" % SECRET_LEN)


def client_proof(secret: bytes, snonce: bytes, cnonce: bytes) -> bytes:
    _check_secret(secret)
    return hmac.new(secret, LABEL_C + snonce + cnonce, hashlib.sha256).digest()


def server_proof(secret: bytes, snonce: bytes, cnonce: bytes) -> bytes:
    _check_secret(secret)
    return hmac.new(secret, LABEL_S + cnonce + snonce, hashlib.sha256).digest()


def parse_secret_hex(text: str) -> bytes:
    raw = bytes.fromhex(text.strip())
    _check_secret(raw)
    return raw


def load_secret(path: str) -> bytes:
    """Read a hex secret file. Refuses group/world-accessible files on POSIX."""
    path = os.path.expanduser(path)
    st = os.stat(path)
    if os.name == "posix" and st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise PermissionError("%s must not be accessible by group/others (chmod 600)" % path)
    with open(path, "r") as f:
        return parse_secret_hex(f.read())


def _recv_exact(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise AuthError("connection closed during handshake (wrong secret, backoff, or API disabled)")
        buf += chunk
    return buf


def handshake(sock, secret: bytes, cnonce: bytes = None) -> None:
    """Run the client side of the handshake on an already connected socket."""
    _check_secret(secret)
    hello = _recv_exact(sock, HELLO_LEN)
    if hello[: len(MAGIC)] != MAGIC:
        raise AuthError("peer is not a QwickMesh authenticated API (bad magic)")
    snonce = hello[len(MAGIC):]
    if cnonce is None:
        cnonce = os.urandom(NONCE_LEN)
    sock.sendall(cnonce + client_proof(secret, snonce, cnonce))
    got = _recv_exact(sock, MAC_LEN)
    if not hmac.compare_digest(got, server_proof(secret, snonce, cnonce)):
        raise AuthError("server proof mismatch: peer does not know the device secret")


def connect(host: str, secret: bytes, port: int = DEFAULT_PORT, timeout: float = 10.0):
    """Connect, authenticate, and return the socket. The caller owns it."""
    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        handshake(sock, secret)
    except BaseException:
        sock.close()
        raise
    sock.settimeout(None)
    return sock


def _make_interface_class():
    from meshtastic.stream_interface import StreamInterface

    class AuthenticatedTCPInterface(StreamInterface):
        """Drop-in for meshtastic.tcp_interface.TCPInterface that authenticates first."""

        def __init__(self, hostname, secret, portNumber=DEFAULT_PORT, debugOut=None, noProto=False,
                     connectNow=True, timeout=10.0):
            self.hostname = hostname
            self.portNumber = portNumber
            self._secret = secret
            self._timeout = timeout
            self.socket = None
            super().__init__(debugOut=debugOut, noProto=noProto, connectNow=connectNow)

        def myConnect(self):
            self.socket = connect(self.hostname, self._secret, self.portNumber, self._timeout)

        def close(self):
            super().close()
            if self.socket is not None:
                try:
                    self.socket.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                self.socket.close()
                self.socket = None

        def _writeBytes(self, b):
            self.socket.send(b)

        def _readBytes(self, length):
            return self.socket.recv(length)

    return AuthenticatedTCPInterface


def __getattr__(name):  # lazy: only imports meshtastic when the interface class is requested
    if name == "AuthenticatedTCPInterface":
        cls = _make_interface_class()
        globals()[name] = cls
        return cls
    raise AttributeError(name)


def _cmd_gen_secret(args):
    secret = os.urandom(SECRET_LEN)
    fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(secret.hex() + "\n")
    print("wrote %s (mode 600); secret not printed" % args.out)


def _cmd_provision(args):
    import serial  # pyserial; only needed here

    secret = load_secret(args.secret_file)
    with serial.Serial(args.port, 115200, timeout=2) as s:
        s.write(b"\nQMAUTH SET " + secret.hex().encode() + b"\n")
        s.flush()
        reply = s.read_until(b"\n").decode(errors="replace").strip()
    print(reply if reply.startswith("QMAUTH") else "no QMAUTH reply (is this a QwickMesh build?)")


def _cmd_check(args):
    connect(args.host, load_secret(args.secret_file), args.port).close()
    print("authenticated OK")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("gen-secret", help="create a random 32 byte secret file (mode 600)")
    g.add_argument("--out", required=True)
    g.set_defaults(fn=_cmd_gen_secret)
    p = sub.add_parser("provision", help="write the secret to the device over USB serial")
    p.add_argument("--port", required=True)
    p.add_argument("--secret-file", required=True)
    p.set_defaults(fn=_cmd_provision)
    c = sub.add_parser("check", help="connect and authenticate, then disconnect")
    c.add_argument("host")
    c.add_argument("--secret-file", required=True)
    c.add_argument("--port", type=int, default=DEFAULT_PORT)
    c.set_defaults(fn=_cmd_check)
    args = ap.parse_args(argv)
    args.fn(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
