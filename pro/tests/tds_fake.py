# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 ETHUX
"""A TDS server that only negotiates TLS, for the MSSQL connector's TLS checks (not a test
module itself).

SQL Server (TDS 7.x) starts TLS inside PRELOGIN packets: the client asks for encryption,
the server agrees, and the TLS handshake travels wrapped in TDS packets; the LOGIN7
packet, which carries the user and password, then goes over the finished TLS session. This
listener plays that part with a certificate a test CA issued for one name. It records what
happened per connection: ``("handshake", None)``, ``("failed", None)``, and, when the
client went on to sign in, ``("login", {...})`` with the user name, application name and
whether the client asked for read-only intent. The password is never decoded. Then it
hangs up.
"""
from __future__ import annotations

import contextlib
import datetime
import os
import socket
import ssl
import struct
import tempfile
import threading

_PRELOGIN = 0x12
_REPLY = 0x04
_READ_ONLY_INTENT = 0x20  # LOGIN7 TypeFlags: fReadOnlyIntent


class TestCa:
    """A throwaway CA that issues server certificates."""

    def __init__(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        self._x509, self._hashes, self._ser, self._ec = x509, hashes, serialization, ec
        self.key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "Erebus Test CA zq")])
        self.cert = self._build(name, name, self.key.public_key(), ca=True)
        self.pem = self.cert.public_bytes(serialization.Encoding.PEM).decode()

    def _build(self, subject, issuer, public_key, *, ca=False, dns=None):
        x509 = self._x509
        now = datetime.datetime.now(datetime.UTC)
        builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(public_key)
                   .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(hours=1))
                   .not_valid_after(now + datetime.timedelta(hours=1))
                   .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
        if dns:
            builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(dns)]), critical=False)
        if ca:
            builder = builder.add_extension(x509.KeyUsage(True, False, False, False, False, True, True, False, False),
                                            critical=True)
        return builder.sign(self.key, self._hashes.SHA256())

    def issue(self, cn):
        """The PEM of a key and a certificate for ``cn``, signed by this CA."""
        key = self._ec.generate_private_key(self._ec.SECP256R1())
        subject = self._x509.Name([self._x509.NameAttribute(self._x509.oid.NameOID.COMMON_NAME, cn)])
        cert = self._build(subject, self.cert.subject, key.public_key(), dns=cn)
        return (key.private_bytes(self._ser.Encoding.PEM, self._ser.PrivateFormat.PKCS8,
                                  self._ser.NoEncryption()).decode()
                + cert.public_bytes(self._ser.Encoding.PEM).decode())


def _packet(kind, data):
    return struct.pack(">BBHHBB", kind, 1, len(data) + 8, 0, 1, 0) + data


def _exact(sock, size):
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise EOFError
        data += chunk
    return data


def _read_packet(sock):
    header = _exact(sock, 8)
    return _exact(sock, struct.unpack(">H", header[2:4])[0] - 8)


def _prelogin_reply():
    # VERSION (16.0.2000) and ENCRYPTION = ENCRYPT_ON, after an option table of two entries.
    table = bytes([0, 0, 11, 0, 6, 1, 0, 17, 0, 1, 0xFF])
    return _packet(_REPLY, table + bytes([16, 0, 7, 0xD0, 0, 0]) + bytes([1]))


def _text(body, at):
    offset, chars = struct.unpack("<HH", body[at:at + 4])
    return body[offset:offset + 2 * chars].decode("utf-16-le")


def _login(body):
    """What a LOGIN7 body says about the client (never the password)."""
    return {"user": _text(body, 40), "app": _text(body, 48), "server": _text(body, 52),
            "read_only": bool(body[26] & _READ_ONLY_INTENT)}


def _handshake(conn, ctx):
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls = ctx.wrap_bio(incoming, outgoing, server_side=True)
    while True:
        try:
            tls.do_handshake()
            break
        except ssl.SSLWantReadError:
            if out := outgoing.read():
                conn.sendall(_packet(_PRELOGIN, out))
            incoming.write(_read_packet(conn))
    if out := outgoing.read():
        conn.sendall(_packet(_PRELOGIN, out))
    return tls, incoming


def _signed_in(conn, tls, incoming):
    """The LOGIN7 the client sends over the finished TLS session, or ``None``."""
    plain = b""
    while len(plain) < 8 or len(plain) < struct.unpack(">H", plain[2:4])[0]:
        try:
            plain += tls.read(65536)
            continue
        except ssl.SSLWantReadError:
            pass
        chunk = conn.recv(65536)
        if not chunk:
            return None
        incoming.write(chunk)
    return _login(plain[8:]) if plain[0] == 0x10 else None


@contextlib.contextmanager
def tds_listener(ca, server_name):
    """Yield ``(port, events)`` for a TLS-only TDS listener on 127.0.0.1."""
    tmp = tempfile.TemporaryDirectory()
    chain = os.path.join(tmp.name, "server.pem")
    with open(chain, "w", encoding="utf-8") as fh:
        fh.write(ca.issue(server_name))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(chain)
    events = []
    srv = socket.create_server(("127.0.0.1", 0))

    def serve():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            conn.settimeout(10)
            try:
                _read_packet(conn)  # the client's PRELOGIN
                conn.sendall(_prelogin_reply())
                tls, incoming = _handshake(conn, ctx)
                events.append(("handshake", None))
                login = _signed_in(conn, tls, incoming)
                if login is not None:
                    events.append(("login", login))
            except (ssl.SSLError, OSError, EOFError):
                events.append(("failed", None))
            finally:
                conn.close()
    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield srv.getsockname()[1], events
    finally:
        srv.close()
        thread.join(5)
        tmp.cleanup()
