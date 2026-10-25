"""Transport base class and shared types."""

from __future__ import annotations

import threading
from typing import Callable, Protocol

# handler(data, addr) -> None
Handler = Callable[[bytes, tuple[str, int]], None]


class TransportError(RuntimeError):
    """Raised for transport-level failures (bind, connect, send)."""


class Transport(Protocol):
    """Minimal transport interface used by the engine and test server."""

    name: str

    def start(self, handler: Handler) -> None:
        """Begin receiving; deliver inbound data to ``handler``."""

    def send(self, data: bytes, addr: tuple[str, int] | None = None) -> None:
        """Send ``data``. ``addr`` may be ignored by connection-oriented transports."""

    def local_addr(self) -> tuple[str, int]:
        """Return the bound ``(host, port)``."""

    def close(self) -> None:
        """Release all resources. Idempotent."""


class BaseTransport:
    """Common bookkeeping shared by concrete transports."""

    def __init__(self) -> None:
        self._handler: Handler | None = None
        self._closed = threading.Event()
        self._lock = threading.Lock()

    def _dispatch(self, data: bytes, addr: tuple[str, int]) -> None:
        handler = self._handler
        if handler is not None and not self._closed.is_set():
            handler(data, addr)
