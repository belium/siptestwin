"""TCP transport with SIP message framing (client connect and server listen).

SIP over a stream transport requires framing each message by its headers plus
``Content-Length`` (RFC 3261 section 18). This transport reassembles the
stream and dispatches one complete SIP message at a time.
"""

from __future__ import annotations

import socket
import ssl
import threading

from .base import BaseTransport, Handler, TransportError

_RECV = 65536


def _frame_messages(buffer: bytearray) -> list[bytes]:
    """Pop all complete SIP messages from ``buffer`` (mutated in place)."""
    messages: list[bytes] = []
    while True:
        sep = buffer.find(b"\r\n\r\n")
        sep_len = 4
        if sep == -1:
            sep = buffer.find(b"\n\n")
            sep_len = 2
            if sep == -1:
                break
        head = bytes(buffer[:sep])
        content_length = 0
        for line in head.split(b"\n"):
            low = line.strip().lower()
            if low.startswith(b"content-length:") or low.startswith(b"l:"):
                try:
                    content_length = int(line.split(b":", 1)[1].strip())
                except (ValueError, IndexError):
                    content_length = 0
                break
        total = sep + sep_len + content_length
        if len(buffer) < total:
            break
        messages.append(bytes(buffer[:total]))
        del buffer[:total]
    return messages


class TCPTransport(BaseTransport):
    """TCP transport. In client mode it connects to a single peer; in server
    mode it listens and services inbound connections."""

    name = "tcp"

    def __init__(
        self,
        *,
        peer: tuple[str, int] | None = None,
        bind: tuple[str, int] | None = None,
        listen: bool = False,
        tls: bool = False,
        verify_tls: bool = True,
        server_side_cert: tuple[str, str] | None = None,
    ) -> None:
        super().__init__()
        self._peer = peer
        self._bind = bind or ("0.0.0.0", 0)
        self._listen = listen
        self._tls = tls
        self._verify_tls = verify_tls
        self._server_cert = server_side_cert
        self.name = "tls" if tls else "tcp"
        self._sock: socket.socket | None = None
        self._conns: dict[tuple[str, int], socket.socket] = {}
        self._threads: list[threading.Thread] = []
        self._bound_addr = self._bind

    # ----- startup --------------------------------------------------------
    def start(self, handler: Handler) -> None:
        self._handler = handler
        if self._listen:
            self._start_server()
        else:
            self._start_client()

    def _wrap_client(self, sock: socket.socket, host: str) -> socket.socket:
        if not self._tls:
            return sock
        ctx = ssl.create_default_context()
        if not self._verify_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx.wrap_socket(sock, server_hostname=host)

    def _start_client(self) -> None:
        if self._peer is None:
            raise TransportError("TCP client requires a peer address")
        host, port = self._peer
        try:
            sock = socket.create_connection((host, port), timeout=10)
            sock = self._wrap_client(sock, host)
        except OSError as exc:
            raise TransportError(f"TCP connect to {self._peer} failed: {exc}") from exc
        sock.settimeout(0.3)
        self._sock = sock
        self._bound_addr = sock.getsockname()[:2]
        self._conns[self._peer] = sock
        t = threading.Thread(target=self._conn_loop, args=(sock, self._peer),
                             name="tcp-client", daemon=True)
        t.start()
        self._threads.append(t)

    def _start_server(self) -> None:
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(self._bind)
            srv.listen(16)
        except OSError as exc:
            raise TransportError(f"TCP listen on {self._bind} failed: {exc}") from exc
        srv.settimeout(0.3)
        if self._tls:
            if not self._server_cert:
                raise TransportError("TLS server requires (certfile, keyfile)")
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(certfile=self._server_cert[0], keyfile=self._server_cert[1])
            self._ssl_ctx: ssl.SSLContext | None = ctx
        else:
            self._ssl_ctx = None
        self._sock = srv
        self._bound_addr = srv.getsockname()[:2]
        t = threading.Thread(target=self._accept_loop, name="tcp-accept", daemon=True)
        t.start()
        self._threads.append(t)

    def _accept_loop(self) -> None:
        assert self._sock is not None
        while not self._closed.is_set():
            try:
                conn, addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                if self._ssl_ctx is not None:
                    conn = self._ssl_ctx.wrap_socket(conn, server_side=True)
            except ssl.SSLError:
                conn.close()
                continue
            conn.settimeout(0.3)
            with self._lock:
                self._conns[addr[:2]] = conn
            ct = threading.Thread(target=self._conn_loop, args=(conn, addr[:2]),
                                  name="tcp-conn", daemon=True)
            ct.start()
            self._threads.append(ct)

    def _conn_loop(self, conn: socket.socket, peer: tuple[str, int]) -> None:
        buffer = bytearray()
        while not self._closed.is_set():
            try:
                chunk = conn.recv(_RECV)
            except socket.timeout:
                continue
            except OSError:
                break
            if not chunk:
                break
            buffer.extend(chunk)
            if len(buffer) > 1_048_576:  # 1 MiB stream safety cap
                buffer.clear()
                break
            for msg in _frame_messages(buffer):
                self._dispatch(msg, peer)
        with self._lock:
            self._conns.pop(peer, None)
        try:
            conn.close()
        except OSError:
            pass

    # ----- send -----------------------------------------------------------
    def send(self, data: bytes, addr: tuple[str, int] | None = None) -> None:
        conn: socket.socket | None
        if addr is not None:
            conn = self._conns.get(addr) or self._conns.get(self._peer) if self._peer else None
            conn = self._conns.get(addr, conn)
        elif self._peer is not None:
            conn = self._conns.get(self._peer)
        else:
            conn = next(iter(self._conns.values()), None)
        if conn is None:
            raise TransportError(f"no TCP connection to {addr or self._peer}")
        try:
            conn.sendall(data)
        except OSError as exc:
            raise TransportError(f"TCP send failed: {exc}") from exc

    def local_addr(self) -> tuple[str, int]:
        return self._bound_addr

    def close(self) -> None:
        self._closed.set()
        with self._lock:
            conns = list(self._conns.values())
            self._conns.clear()
        for c in conns:
            try:
                c.close()
            except OSError:
                pass
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        for t in self._threads:
            if t.is_alive():
                t.join(timeout=1.0)
