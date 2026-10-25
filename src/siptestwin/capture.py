"""SIP message tracing and capture.

Provides a thread-safe tracer that records every SIP message the engine sends
or receives, in up to three sinks:

* **console** — a compact one-line-per-message ladder (with the first line of
  each SIP message), optionally with the full message;
* **text** — a human-readable ``.trace.log`` with timestamps and full messages
  (credential hashes redacted, consistent with the audit policy);
* **pcap** — a Wireshark-openable capture. Each SIP message is wrapped in
  synthesized Ethernet/IPv4/UDP headers so Wireshark dissects it as SIP. This
  is a true wire capture: SIP Digest never transmits the plaintext password,
  so no plaintext secret can appear here.

No external tools (tshark/npcap) are required to produce the pcap.
"""

from __future__ import annotations

import socket
import struct
import threading
import time
from pathlib import Path

from .safety import redact

_LINKTYPE_ETHERNET = 1


def _resolve_ipv4(host: str) -> bytes:
    try:
        return socket.inet_aton(socket.gethostbyname(host))
    except (OSError, ValueError):
        return socket.inet_aton("0.0.0.0")


def _ip_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def _synthesize_udp_packet(src_ip: str, src_port: int, dst_ip: str,
                           dst_port: int, payload: bytes) -> bytes:
    """Build an Ethernet+IPv4+UDP frame carrying ``payload`` (for pcap)."""
    # Ethernet header: locally-administered placeholder MACs, IPv4 ethertype.
    eth = b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01" + b"\x08\x00"

    udp_len = 8 + len(payload)
    udp = struct.pack("!HHHH", src_port & 0xFFFF, dst_port & 0xFFFF, udp_len, 0) + payload

    total_len = 20 + udp_len
    src = _resolve_ipv4(src_ip)
    dst = _resolve_ipv4(dst_ip)
    ip_no_csum = struct.pack(
        "!BBHHHBBH", 0x45, 0x00, total_len, 0x0000, 0x4000, 64, 17, 0
    ) + src + dst
    csum = _ip_checksum(ip_no_csum)
    ip = ip_no_csum[:10] + struct.pack("!H", csum) + ip_no_csum[12:]
    return eth + ip + udp


class PcapWriter:
    """Minimal classic-format (libpcap) writer, Ethernet link type."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = self.path.open("wb")
        # Global header.
        self._fh.write(struct.pack("!IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535,
                                   _LINKTYPE_ETHERNET))
        self._fh.flush()

    def write(self, frame: bytes, ts: float) -> None:
        sec = int(ts)
        usec = int((ts - sec) * 1_000_000)
        self._fh.write(struct.pack("!IIII", sec, usec, len(frame), len(frame)))
        self._fh.write(frame)
        self._fh.flush()

    def close(self) -> None:
        try:
            self._fh.close()
        except OSError:
            pass


class SipTracer:
    """Records sent/received SIP messages to console/text/pcap sinks."""

    def __init__(
        self,
        *,
        to_console: bool = False,
        text_path: str | Path | None = None,
        pcap_path: str | Path | None = None,
        console_full: bool = False,
        console_print=None,
    ) -> None:
        self.to_console = to_console
        self.console_full = console_full
        self._print = console_print or print
        self._lock = threading.Lock()
        self._count = 0

        self.text_path = str(text_path) if text_path else None
        self.pcap_path = str(pcap_path) if pcap_path else None

        self._text = None
        if text_path:
            p = Path(text_path)
            p.parent.mkdir(parents=True, exist_ok=True)
            self._text = p.open("w", encoding="utf-8")
            self._text.write(f"# SIPTestWin SIP trace - {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")

        self._pcap = PcapWriter(pcap_path) if pcap_path else None

        # Bound by the engine once the transport local address is known.
        self.local_ip = "0.0.0.0"
        self.local_port = 0
        self.target_ip = "0.0.0.0"
        self.transport = "udp"

    def bind(self, local_ip: str, local_port: int, target_ip: str, transport: str) -> None:
        self.local_ip = local_ip
        self.local_port = local_port or 0
        self.target_ip = target_ip
        self.transport = transport

    @property
    def enabled(self) -> bool:
        return self.to_console or self._text is not None or self._pcap is not None

    def record(self, direction: str, data: bytes, peer: tuple[str, int]) -> None:
        """direction: 'sent' or 'recv'. ``peer`` is the remote (host, port)."""
        ts = time.time()
        first_line = data.split(b"\r\n", 1)[0].decode("utf-8", errors="replace")
        arrow = "->" if direction == "sent" else "<-"
        peer_ip, peer_port = peer[0], peer[1]

        with self._lock:
            self._count += 1
            seq = self._count

            if self.to_console:
                stamp = time.strftime("%H:%M:%S", time.localtime(ts))
                self._print(f"[trace {seq:>3}] {stamp} {arrow} {peer_ip}:{peer_port}  {first_line}")
                if self.console_full:
                    self._print(redact(data.decode("utf-8", errors="replace")))

            if self._text is not None:
                stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
                hdr = (f"===== #{seq} {direction.upper()} {arrow} {peer_ip}:{peer_port} "
                       f"({self.transport.upper()}) {stamp} =====\n")
                body = redact(data.decode("utf-8", errors="replace"))
                self._text.write(hdr + body.rstrip("\r\n") + "\n\n")
                self._text.flush()

            if self._pcap is not None:
                if direction == "sent":
                    frame = _synthesize_udp_packet(self.local_ip, self.local_port,
                                                   peer_ip, peer_port, data)
                else:
                    frame = _synthesize_udp_packet(peer_ip, peer_port,
                                                   self.local_ip, self.local_port, data)
                self._pcap.write(frame, ts)

    def close(self) -> None:
        with self._lock:
            if self._text is not None:
                try:
                    self._text.close()
                except OSError:
                    pass
                self._text = None
            if self._pcap is not None:
                self._pcap.close()
                self._pcap = None

    def paths(self) -> list[str]:
        out = []
        if self.text_path:
            out.append(self.text_path)
        if self.pcap_path:
            out.append(self.pcap_path)
        return out
