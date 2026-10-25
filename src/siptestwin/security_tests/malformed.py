"""Controlled malformed-input catalog for robustness testing.

This produces a *small, fixed* set of individually malformed requests to check
that a server rejects them gracefully (typically with a 4xx) rather than
crashing. It is deliberately bounded: one message per case, no flooding, no
fuzzing at volume. Each case documents what it violates and the expected
graceful handling.
"""

from __future__ import annotations

from dataclasses import dataclass

from .. import sip_message as sip
from ..sip_message import SIPMessage


@dataclass
class MalformedCase:
    name: str
    description: str
    expected: str                 # description of acceptable server behaviour
    message: SIPMessage


def _base_options(local_ip: str, target_host: str, target_port: int) -> SIPMessage:
    return sip.build_request(
        "OPTIONS",
        f"sip:{target_host}",
        from_uri="<sip:tester@lab.example>",
        to_uri=f"<sip:probe@{target_host}>",
        call_id=sip.new_call_id(local_ip),
        cseq=1,
        via_host=local_ip,
        via_port=target_port,
        from_tag=sip.new_tag(),
    )


def malformed_catalog(local_ip: str, target_host: str, target_port: int) -> list[MalformedCase]:
    """Return the fixed catalog of controlled malformed requests."""
    cases: list[MalformedCase] = []

    # 1. Missing mandatory Call-ID.
    m = _base_options(local_ip, target_host, target_port)
    m.headers.remove("Call-ID")
    cases.append(MalformedCase(
        "missing-call-id", "OPTIONS with the mandatory Call-ID header removed",
        "server should reject (e.g. 400 Bad Request), not crash", m))

    # 2. CSeq method mismatch.
    m = _base_options(local_ip, target_host, target_port)
    m.headers.set("CSeq", "1 INVITE")
    cases.append(MalformedCase(
        "cseq-method-mismatch", "CSeq method does not match the request method",
        "server should reject with 4xx", m))

    # 3. Via without branch.
    m = _base_options(local_ip, target_host, target_port)
    m.headers.set("Via", f"SIP/2.0/UDP {local_ip}:{target_port}")
    cases.append(MalformedCase(
        "via-no-branch", "top Via missing the required branch parameter",
        "server should reject with 4xx", m))

    # 4. Negative Max-Forwards.
    m = _base_options(local_ip, target_host, target_port)
    m.headers.set("Max-Forwards", "-1")
    cases.append(MalformedCase(
        "negative-max-forwards", "Max-Forwards set to a negative value",
        "server should reject with 4xx", m))

    # 5. Content-Length larger than the (empty) body.
    m = _base_options(local_ip, target_host, target_port)
    m.headers.set("Content-Length", "500")
    cases.append(MalformedCase(
        "content-length-overstated", "Content-Length claims 500 bytes for an empty body",
        "server should not hang waiting for a body; reject or time out cleanly", m))

    # 6. Duplicated From header.
    m = _base_options(local_ip, target_host, target_port)
    m.headers.add("From", "<sip:duplicate@lab.example>;tag=dup")
    cases.append(MalformedCase(
        "duplicate-from", "two From headers present",
        "server should reject with 4xx", m))

    return cases
