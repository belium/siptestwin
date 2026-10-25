"""Pluggable SIP transports (UDP, TCP; TLS optional).

Transports move bytes; they have no knowledge of SIP semantics. A transport
delivers inbound data to a handler callback ``handler(data: bytes, addr)`` and
exposes ``send(data, addr=None)``.
"""

from .base import Transport, TransportError
from .factory import create_transport

__all__ = ["Transport", "TransportError", "create_transport"]
