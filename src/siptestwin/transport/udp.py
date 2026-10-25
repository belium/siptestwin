"""UDP transport (connectionless)."""

from __future__ import annotations

import socket
import threading

from .base import BaseTransport, Handler, TransportError

MAX_DATAGRAM = 65535


class UDPTransport(BaseTransport):
    """A UDP socket that can both send to a peer and receive datagrams.

    Works on Windows without special privileges. Binding to port 0 lets the OS
    pick an ephemeral source port, which is the default for a test client.
    """

    name = "udp"

    def __init__(self, bind_host: str = "0.0.0.0", bind_port: int = 0) -> None:
        super().__init__()
        self._bind = (bind_host, bind_port)
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None

    def start(self, handler: Handler) -> None:
        self._handler = handler
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(self._bind)
        except OSError as exc:
            raise TransportError(f"UDP bind failed on {self._bind}: {exc}") from exc
        sock.settimeout(0.3)
        self._sock = sock
        self._thread = threading.Thread(target=self._recv_loop, name="udp-recv", daemon=True)
        self._thread.start()

    def _recv_loop(self) -> None:
        assert self._sock is not None
        while not self._closed.is_set():
            try:
                data, addr = self._sock.recvfrom(MAX_DATAGRAM)
            except socket.timeout:
                continue
            except OSError:
                break
            if data:
                self._dispatch(data, addr)

    def send(self, data: bytes, addr: tuple[str, int] | None = None) -> None:
        if self._sock is None:
            raise TransportError("UDP transport not started")
        if addr is None:
            raise TransportError("UDP send requires a destination address")
        if len(data) > MAX_DATAGRAM:
            raise TransportError(f"datagram too large: {len(data)} bytes")
        try:
            self._sock.sendto(data, addr)
        except OSError as exc:
            raise TransportError(f"UDP send to {addr} failed: {exc}") from exc

    def local_addr(self) -> tuple[str, int]:
        if self._sock is None:
            return self._bind
        return self._sock.getsockname()

    def close(self) -> None:
        self._closed.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.0)
        if self._sock is not None:
            with self._lock:
                try:
                    self._sock.close()
                finally:
                    self._sock = None
