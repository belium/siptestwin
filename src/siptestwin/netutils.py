"""Local network helpers: enumerate usable source IPv4 addresses.

Used by the ``interfaces`` CLI command and to help the operator choose which
local IP to trace / bind on (``execution.local_host``). Pure standard library,
no external dependencies, works on Windows.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass


@dataclass
class LocalAddress:
    ip: str
    label: str          # "loopback", "private", "public", "link-local"
    is_loopback: bool


def _classify(ip: str) -> tuple[str, bool]:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "unknown", False
    if addr.is_loopback:
        return "loopback", True
    if addr.is_link_local:
        return "link-local", False
    if addr.is_private:
        return "private", False
    return "public", False


def list_local_ipv4() -> list[LocalAddress]:
    """Return the distinct IPv4 addresses this host can bind as a source.

    Combines the hostname resolution and the "connect a UDP socket to a public
    address and read the chosen source" trick (which reveals the default-route
    interface IP) without sending any packets.
    """
    found: dict[str, LocalAddress] = {}

    def add(ip: str) -> None:
        if not ip or ip in found:
            return
        label, loop = _classify(ip)
        found[ip] = LocalAddress(ip=ip, label=label, is_loopback=loop)

    # Always include loopback (used for local lab testing).
    add("127.0.0.1")

    # Hostname-resolved addresses.
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            add(info[4][0])
    except (socket.gaierror, OSError):
        pass

    # Default-route source IP (no packet is actually sent for UDP connect).
    for probe in ("8.8.8.8", "192.0.2.1"):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.connect((probe, 9))
                add(s.getsockname()[0])
            finally:
                s.close()
        except OSError:
            continue

    # Order: non-loopback private first, then public, link-local, loopback last.
    order = {"private": 0, "public": 1, "link-local": 2, "unknown": 3, "loopback": 4}
    return sorted(found.values(), key=lambda a: (order.get(a.label, 3), a.ip))


def default_local_ip(target_host: str = "8.8.8.8", target_port: int = 9) -> str:
    """Best-effort default source IP toward ``target_host`` (no packet sent)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect((target_host, target_port))
            return s.getsockname()[0]
        finally:
            s.close()
    except OSError:
        return "127.0.0.1"


def is_local_ip(ip: str) -> bool:
    """True if ``ip`` is one of this host's bindable IPv4 addresses."""
    return any(a.ip == ip for a in list_local_ipv4())
