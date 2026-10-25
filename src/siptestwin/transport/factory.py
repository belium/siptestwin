"""Factory for building transports from configuration."""

from __future__ import annotations

from .base import Transport, TransportError
from .tcp import TCPTransport
from .udp import UDPTransport


def create_transport(
    transport: str,
    *,
    peer: tuple[str, int] | None = None,
    bind_host: str = "0.0.0.0",
    bind_port: int = 0,
    verify_tls: bool = True,
) -> Transport:
    """Create a client-mode transport of the requested kind.

    ``transport`` is one of ``udp``, ``tcp`` or ``tls`` (case-insensitive).
    """
    kind = transport.lower()
    if kind == "udp":
        return UDPTransport(bind_host=bind_host, bind_port=bind_port)
    if kind == "tcp":
        return TCPTransport(peer=peer, bind=(bind_host, bind_port))
    if kind == "tls":
        return TCPTransport(peer=peer, bind=(bind_host, bind_port), tls=True,
                            verify_tls=verify_tls)
    raise TransportError(f"unsupported transport: {transport!r}")
