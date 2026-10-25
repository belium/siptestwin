"""Protocol-validation checks for SIP messages and response sequences."""

from __future__ import annotations

from dataclasses import dataclass

from ..sip_message import SIPMessage

# Mandatory headers in any SIP request (RFC 3261 section 8.1.1).
MANDATORY_REQUEST_HEADERS = ("Via", "From", "To", "Call-ID", "CSeq", "Max-Forwards")
MANDATORY_RESPONSE_HEADERS = ("Via", "From", "To", "Call-ID", "CSeq")


@dataclass
class ProtocolFinding:
    severity: str   # "error" | "warning" | "info"
    rule: str
    detail: str


def validate_message(msg: SIPMessage) -> list[ProtocolFinding]:
    """Validate structural conformance of a request or response."""
    findings: list[ProtocolFinding] = []
    required = MANDATORY_REQUEST_HEADERS if msg.is_request else MANDATORY_RESPONSE_HEADERS
    for header in required:
        if header not in msg.headers:
            findings.append(ProtocolFinding("error", "missing-header",
                                            f"mandatory header {header} is absent"))

    # These headers must appear exactly once (RFC 3261 section 8.1.1 / 20).
    for header in ("From", "To", "Call-ID", "CSeq", "Max-Forwards"):
        if len(msg.headers.get_all(header)) > 1:
            findings.append(ProtocolFinding("error", "duplicate-header",
                                            f"{header} appears more than once"))

    cseq = msg.headers.get("CSeq")
    if cseq:
        parts = cseq.split()
        if len(parts) != 2 or not parts[0].isdigit():
            findings.append(ProtocolFinding("error", "bad-cseq", f"malformed CSeq: {cseq!r}"))
        elif msg.is_request and parts[1].upper() != (msg.method or "").upper():
            findings.append(ProtocolFinding("error", "cseq-method-mismatch",
                                            f"CSeq method {parts[1]} != {msg.method}"))

    via = msg.headers.get("Via")
    if via and "branch=" not in via:
        findings.append(ProtocolFinding("error", "via-no-branch",
                                        "top Via lacks a branch parameter"))
    if via and "z9hG4bK" not in (via.split("branch=")[-1] if "branch=" in via else ""):
        findings.append(ProtocolFinding("warning", "via-branch-cookie",
                                        "Via branch missing RFC 3261 magic cookie"))

    if msg.is_request and msg.headers.get("Max-Forwards"):
        try:
            mf = int(msg.headers.get("Max-Forwards"))
            if mf < 0:
                findings.append(ProtocolFinding("error", "bad-max-forwards",
                                                "Max-Forwards is negative"))
        except ValueError:
            findings.append(ProtocolFinding("error", "bad-max-forwards",
                                            "Max-Forwards is not an integer"))

    cl = msg.headers.get("Content-Length")
    if cl is not None:
        try:
            if int(cl) != len(msg.body):
                findings.append(ProtocolFinding("warning", "content-length-mismatch",
                                                f"Content-Length {cl} != body {len(msg.body)}"))
        except ValueError:
            findings.append(ProtocolFinding("error", "bad-content-length",
                                            f"Content-Length not an integer: {cl!r}"))
    return findings


def validate_response_sequence(codes: list[int]) -> list[ProtocolFinding]:
    """Validate that a sequence of response codes for a request is plausible."""
    findings: list[ProtocolFinding] = []
    if not codes:
        findings.append(ProtocolFinding("warning", "no-response", "no responses received"))
        return findings
    finals = [c for c in codes if c >= 200]
    if len(finals) == 0:
        findings.append(ProtocolFinding("warning", "no-final",
                                        "only provisional responses received"))
    # Provisional after final is a protocol violation.
    seen_final = False
    for c in codes:
        if c >= 200:
            seen_final = True
        elif seen_final:
            findings.append(ProtocolFinding("error", "provisional-after-final",
                                            f"provisional {c} after a final response"))
    return findings
