"""SIP message model: parsing and construction (RFC 3261).

This module provides a transport-agnostic representation of SIP requests and
responses, a tolerant parser, and helpers to build well-formed messages with
correctly generated Call-ID, tags, branch parameters and CSeq values.

Only the subset of RFC 3261 needed for OPTIONS / REGISTER / INVITE / ACK /
CANCEL / BYE testing is implemented, but the structure is general.
"""

from __future__ import annotations

import os
import secrets
import time
from dataclasses import dataclass, field
from typing import Iterable

CRLF = "\r\n"
MAGIC_COOKIE = "z9hG4bK"  # RFC 3261 Via branch magic cookie
MAX_MESSAGE_BYTES = 64 * 1024  # hard cap to avoid unbounded parsing

# Methods we understand. Unknown methods are still parseable but flagged.
KNOWN_METHODS = {
    "INVITE", "ACK", "BYE", "CANCEL", "OPTIONS", "REGISTER",
    "INFO", "PRACK", "UPDATE", "SUBSCRIBE", "NOTIFY", "REFER", "MESSAGE",
}

# Compact header forms -> canonical names (RFC 3261 section 20, 7.3.3).
_COMPACT = {
    "i": "Call-ID", "m": "Contact", "e": "Content-Encoding",
    "l": "Content-Length", "c": "Content-Type", "f": "From",
    "s": "Subject", "k": "Supported", "t": "To", "v": "Via",
    "r": "Refer-To", "b": "Referred-By", "o": "Event",
}


class SIPParseError(ValueError):
    """Raised when a byte string cannot be parsed as a SIP message."""


def canonical_header(name: str) -> str:
    """Return the canonical, case-correct header name."""
    key = name.strip()
    low = key.lower()
    if len(low) == 1 and low in _COMPACT:
        return _COMPACT[low]
    # Title-case each hyphen-separated token but keep known special spellings.
    special = {
        "call-id": "Call-ID", "cseq": "CSeq", "www-authenticate": "WWW-Authenticate",
        "mime-version": "MIME-Version", "sip-etag": "SIP-ETag", "sip-if-match": "SIP-If-Match",
    }
    if low in special:
        return special[low]
    return "-".join(part[:1].upper() + part[1:] for part in low.split("-"))


class Headers:
    """Ordered, case-insensitive multi-value header container.

    Preserves insertion order and allows multiple values for the same header
    name (e.g. multiple Via lines), which SIP requires.
    """

    def __init__(self) -> None:
        self._items: list[tuple[str, str]] = []

    def add(self, name: str, value: str) -> None:
        self._items.append((canonical_header(name), str(value)))

    def set(self, name: str, value: str) -> None:
        """Replace all existing values for ``name`` with a single value."""
        cname = canonical_header(name)
        self._items = [(n, v) for (n, v) in self._items if n != cname]
        self._items.append((cname, str(value)))

    def get(self, name: str, default: str | None = None) -> str | None:
        """Return the first value for ``name`` (top-most)."""
        cname = canonical_header(name)
        for n, v in self._items:
            if n == cname:
                return v
        return default

    def get_all(self, name: str) -> list[str]:
        cname = canonical_header(name)
        return [v for n, v in self._items if n == cname]

    def remove(self, name: str) -> None:
        cname = canonical_header(name)
        self._items = [(n, v) for (n, v) in self._items if n != cname]

    def names(self) -> list[str]:
        seen: list[str] = []
        for n, _ in self._items:
            if n not in seen:
                seen.append(n)
        return seen

    def items(self) -> list[tuple[str, str]]:
        return list(self._items)

    def __contains__(self, name: str) -> bool:
        return self.get(name) is not None

    def __iter__(self) -> Iterable[tuple[str, str]]:
        return iter(self._items)


@dataclass
class SIPMessage:
    """A SIP request or response."""

    # For requests:
    method: str | None = None
    request_uri: str | None = None
    # For responses:
    status_code: int | None = None
    reason_phrase: str | None = None
    # Common:
    version: str = "SIP/2.0"
    headers: Headers = field(default_factory=Headers)
    body: bytes = b""

    # ----- classification -------------------------------------------------
    @property
    def is_request(self) -> bool:
        return self.method is not None

    @property
    def is_response(self) -> bool:
        return self.status_code is not None

    @property
    def is_provisional(self) -> bool:
        return self.is_response and 100 <= (self.status_code or 0) < 200

    @property
    def is_final(self) -> bool:
        return self.is_response and (self.status_code or 0) >= 200

    # ----- convenience header accessors ----------------------------------
    @property
    def call_id(self) -> str | None:
        return self.headers.get("Call-ID")

    @property
    def cseq_number(self) -> int | None:
        raw = self.headers.get("CSeq")
        if not raw:
            return None
        try:
            return int(raw.split()[0])
        except (ValueError, IndexError):
            return None

    @property
    def cseq_method(self) -> str | None:
        raw = self.headers.get("CSeq")
        if not raw:
            return None
        parts = raw.split()
        return parts[1].upper() if len(parts) > 1 else None

    def top_via_branch(self) -> str | None:
        via = self.headers.get("Via")
        if not via:
            return None
        return _extract_param(via, "branch")

    def from_tag(self) -> str | None:
        return _extract_param(self.headers.get("From", ""), "tag")

    def to_tag(self) -> str | None:
        return _extract_param(self.headers.get("To", ""), "tag")

    # ----- serialization --------------------------------------------------
    def serialize(self) -> bytes:
        """Return the on-the-wire byte representation.

        Content-Length is always recomputed to match the body so that
        manually assembled messages stay consistent.
        """
        if self.is_request:
            start = f"{self.method} {self.request_uri} {self.version}"
        elif self.is_response:
            start = f"{self.version} {self.status_code} {self.reason_phrase or ''}".rstrip()
        else:
            raise SIPParseError("message is neither a request nor a response")

        self.headers.set("Content-Length", str(len(self.body)))
        lines = [start]
        for name, value in self.headers.items():
            lines.append(f"{name}: {value}")
        head = CRLF.join(lines) + CRLF + CRLF
        return head.encode("utf-8") + self.body

    def __str__(self) -> str:  # pragma: no cover - debugging aid
        return self.serialize().decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def _split_head_body(data: bytes) -> tuple[bytes, bytes]:
    idx = data.find(b"\r\n\r\n")
    if idx != -1:
        return data[:idx], data[idx + 4:]
    idx = data.find(b"\n\n")  # tolerate LF-only separators
    if idx != -1:
        return data[:idx], data[idx + 2:]
    return data, b""


def parse(data: bytes, *, strict: bool = False) -> SIPMessage:
    """Parse ``data`` into a :class:`SIPMessage`.

    With ``strict=False`` (default) the parser tolerates LF-only line endings
    and does not require Content-Length. With ``strict=True`` it rejects such
    deviations, which is useful for protocol-validation security tests.
    """
    if len(data) > MAX_MESSAGE_BYTES:
        raise SIPParseError(f"message exceeds {MAX_MESSAGE_BYTES} bytes")
    if not data.strip():
        raise SIPParseError("empty message")

    head, body = _split_head_body(data)
    text = head.decode("utf-8", errors="replace")
    # Unfold continuation lines (a line starting with SP/HTAB continues prev).
    raw_lines = text.split("\r\n") if "\r\n" in text else text.split("\n")
    lines: list[str] = []
    for ln in raw_lines:
        if ln[:1] in (" ", "\t") and lines:
            lines[-1] += " " + ln.strip()
        else:
            lines.append(ln)
    if not lines or not lines[0].strip():
        raise SIPParseError("missing start line")

    msg = SIPMessage()
    start = lines[0]
    if start.startswith("SIP/"):
        parts = start.split(" ", 2)
        if len(parts) < 2:
            raise SIPParseError(f"malformed status line: {start!r}")
        msg.version = parts[0]
        try:
            msg.status_code = int(parts[1])
        except ValueError as exc:
            raise SIPParseError(f"invalid status code: {parts[1]!r}") from exc
        msg.reason_phrase = parts[2] if len(parts) > 2 else ""
    else:
        parts = start.split(" ")
        if len(parts) != 3:
            raise SIPParseError(f"malformed request line: {start!r}")
        msg.method, msg.request_uri, msg.version = parts
        if strict and msg.method not in KNOWN_METHODS:
            raise SIPParseError(f"unknown method: {msg.method!r}")

    for ln in lines[1:]:
        if not ln:
            continue
        if ":" not in ln:
            if strict:
                raise SIPParseError(f"malformed header line: {ln!r}")
            continue
        name, _, value = ln.partition(":")
        msg.headers.add(name.strip(), value.strip())

    # Honour declared Content-Length when present (truncate/accept body).
    cl = msg.headers.get("Content-Length")
    if cl is not None:
        try:
            n = int(cl)
        except ValueError as exc:
            if strict:
                raise SIPParseError(f"invalid Content-Length: {cl!r}") from exc
            n = len(body)
        if n >= 0:
            if strict and n != len(body):
                raise SIPParseError(
                    f"Content-Length {n} does not match body {len(body)}"
                )
            body = body[:n]
    msg.body = body
    return msg


# ---------------------------------------------------------------------------
# Parameter + identifier helpers
# ---------------------------------------------------------------------------

def _extract_param(header_value: str, param: str) -> str | None:
    """Extract ``;param=value`` from a header value (handles quotes)."""
    for seg in header_value.split(";")[1:]:
        if "=" in seg:
            k, _, v = seg.partition("=")
            if k.strip().lower() == param.lower():
                return v.strip().strip('"')
        elif seg.strip().lower() == param.lower():
            return ""
    return None


def new_branch() -> str:
    """Generate an RFC 3261 compliant unique Via branch."""
    return MAGIC_COOKIE + secrets.token_hex(12)


def new_call_id(host: str = "siptestwin.local") -> str:
    return f"{secrets.token_hex(12)}@{host}"


def new_tag() -> str:
    return secrets.token_hex(6)


# ---------------------------------------------------------------------------
# Request / response builders
# ---------------------------------------------------------------------------

def build_request(
    method: str,
    request_uri: str,
    *,
    from_uri: str,
    to_uri: str,
    call_id: str,
    cseq: int,
    via_host: str,
    via_port: int,
    transport: str = "UDP",
    from_tag: str | None = None,
    to_tag: str | None = None,
    contact: str | None = None,
    branch: str | None = None,
    max_forwards: int = 70,
    extra_headers: dict[str, str] | None = None,
    body: bytes = b"",
    user_agent: str = "SIPTestWin/0.1",
) -> SIPMessage:
    """Build a well-formed SIP request with all mandatory headers."""
    msg = SIPMessage(method=method.upper(), request_uri=request_uri)
    branch = branch or new_branch()
    msg.headers.add(
        "Via",
        f"SIP/2.0/{transport.upper()} {via_host}:{via_port};branch={branch};rport",
    )
    msg.headers.add("Max-Forwards", str(max_forwards))
    from_val = from_uri
    if from_tag:
        from_val += f";tag={from_tag}"
    msg.headers.add("From", from_val)
    to_val = to_uri
    if to_tag:
        to_val += f";tag={to_tag}"
    msg.headers.add("To", to_val)
    msg.headers.add("Call-ID", call_id)
    msg.headers.add("CSeq", f"{cseq} {method.upper()}")
    if contact:
        msg.headers.add("Contact", contact)
    msg.headers.add("User-Agent", user_agent)
    if extra_headers:
        for k, v in extra_headers.items():
            msg.headers.add(k, v)
    msg.body = body
    msg.headers.set("Content-Length", str(len(body)))
    return msg


def build_response(
    request: SIPMessage,
    status_code: int,
    reason_phrase: str | None = None,
    *,
    to_tag: str | None = None,
    contact: str | None = None,
    extra_headers: dict[str, str] | None = None,
    body: bytes = b"",
) -> SIPMessage:
    """Build a response to ``request`` echoing mandatory headers (RFC 3261 8.2.6)."""
    resp = SIPMessage(status_code=status_code, reason_phrase=reason_phrase or _reason(status_code))
    # Copy Via (all), From, Call-ID, CSeq verbatim; To gets a tag for non-100.
    for via in request.headers.get_all("Via"):
        resp.headers.add("Via", via)
    resp.headers.add("From", request.headers.get("From", ""))
    to_val = request.headers.get("To", "")
    if to_tag and "tag=" not in to_val and status_code != 100:
        to_val += f";tag={to_tag}"
    resp.headers.add("To", to_val)
    resp.headers.add("Call-ID", request.headers.get("Call-ID", ""))
    resp.headers.add("CSeq", request.headers.get("CSeq", ""))
    if contact:
        resp.headers.add("Contact", contact)
    if extra_headers:
        for k, v in extra_headers.items():
            resp.headers.add(k, v)
    resp.body = body
    resp.headers.set("Content-Length", str(len(body)))
    return resp


_REASONS = {
    100: "Trying", 180: "Ringing", 181: "Call Is Being Forwarded",
    182: "Queued", 183: "Session Progress",
    200: "OK", 202: "Accepted",
    300: "Multiple Choices", 301: "Moved Permanently", 302: "Moved Temporarily",
    305: "Use Proxy", 380: "Alternative Service",
    400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found",
    405: "Method Not Allowed", 406: "Not Acceptable", 407: "Proxy Authentication Required",
    408: "Request Timeout", 413: "Request Entity Too Large",
    414: "Request-URI Too Long", 415: "Unsupported Media Type",
    420: "Bad Extension", 423: "Interval Too Brief", 480: "Temporarily Unavailable",
    481: "Call/Transaction Does Not Exist", 482: "Loop Detected", 483: "Too Many Hops",
    486: "Busy Here", 487: "Request Terminated", 488: "Not Acceptable Here",
    500: "Server Internal Error", 501: "Not Implemented", 503: "Service Unavailable",
    504: "Server Time-out", 600: "Busy Everywhere", 603: "Decline",
}


def _reason(code: int) -> str:
    return _REASONS.get(code, "Unknown")


def generate_sdp(host: str, port: int = 8000, session_id: int | None = None) -> bytes:
    """Produce a minimal, valid SDP offer body for INVITE testing."""
    sid = session_id if session_id is not None else int(time.time())
    sdp = (
        "v=0\r\n"
        f"o=siptestwin {sid} {sid} IN IP4 {host}\r\n"
        "s=SIPTestWin Session\r\n"
        f"c=IN IP4 {host}\r\n"
        "t=0 0\r\n"
        f"m=audio {port} RTP/AVP 0 8\r\n"
        "a=rtpmap:0 PCMU/8000\r\n"
        "a=rtpmap:8 PCMA/8000\r\n"
        "a=sendrecv\r\n"
    )
    return sdp.encode("utf-8")


def process_id() -> int:
    """Return the current process id (used for deterministic session ids)."""
    return os.getpid()
