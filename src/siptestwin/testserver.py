"""A minimal local SIP test server (UAS simulator) for loopback validation.

This is NOT a production SIP server. It implements just enough behaviour to
exercise SIPTestWin end-to-end on localhost without any external system:

* OPTIONS   -> 200 OK (or 405 for a configured unsupported method)
* REGISTER  -> 401 challenge, then 200 OK once a valid Digest response arrives
* INVITE    -> 100 Trying, 180 Ringing, 200 OK (expects ACK)
* BYE       -> 200 OK
* CANCEL    -> 200 OK
* malformed -> 400 Bad Request

It binds to loopback by default. It exists so that tests and demos never need
to point at a third-party server.
"""

from __future__ import annotations

import hashlib
import secrets
import threading
import time

from . import sip_message as sip
from .authentication.digest import _parse_params
from .sip_message import SIPMessage
from .transport.tcp import TCPTransport
from .transport.udp import UDPTransport

REALM = "siptestwin.lab"


class TestSIPServer:
    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 0,
        *,
        transport: str = "udp",
        require_auth: bool = False,
        username: str = "tester",
        password: str = "labpass",
        unsupported_methods: tuple[str, ...] = (),
    ) -> None:
        self.host = host
        self.require_auth = require_auth
        self.username = username
        self.password = password
        self.unsupported = {m.upper() for m in unsupported_methods}
        self._nonce = secrets.token_hex(16)
        self.received: list[SIPMessage] = []
        self._lock = threading.Lock()

        if transport.lower() == "udp":
            self._transport = UDPTransport(bind_host=host, bind_port=port)
        else:
            self._transport = TCPTransport(bind=(host, port), listen=True)
        self._transport_name = transport.upper()

    # ----- lifecycle ------------------------------------------------------
    def start(self) -> "TestSIPServer":
        self._transport.start(self._on_message)
        return self

    @property
    def port(self) -> int:
        return self._transport.local_addr()[1]

    def stop(self) -> None:
        self._transport.close()

    def __enter__(self) -> "TestSIPServer":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()

    # ----- request handling ----------------------------------------------
    def _on_message(self, data: bytes, addr: tuple[str, int]) -> None:
        try:
            msg = sip.parse(data, strict=False)
        except sip.SIPParseError:
            return
        if not msg.is_request:
            return
        with self._lock:
            self.received.append(msg)

        resp = self._handle(msg)
        for r in resp:
            self._transport.send(r.serialize(), addr)

    def _handle(self, req: SIPMessage) -> list[SIPMessage]:
        problem = self._protocol_problem(req)
        if problem:
            return [sip.build_response(req, 400, problem)]

        method = (req.method or "").upper()
        if method in self.unsupported:
            return [sip.build_response(req, 405, "Method Not Allowed",
                                       extra_headers={"Allow": "INVITE, ACK, BYE, CANCEL, OPTIONS"})]
        if method == "OPTIONS":
            return [sip.build_response(req, 200, extra_headers={
                "Allow": "INVITE, ACK, CANCEL, BYE, OPTIONS, REGISTER",
                "Accept": "application/sdp",
            })]
        if method == "REGISTER":
            return self._handle_auth(req, 401, "WWW-Authenticate")
        if method == "INVITE":
            if self.require_auth:
                auth = self._handle_auth(req, 407, "Proxy-Authenticate")
                if auth[0].status_code != 200:
                    return auth
            return self._invite_responses(req)
        if method in ("ACK",):
            return []  # ACK is not answered
        if method == "BYE":
            return [sip.build_response(req, 200, to_tag=sip.new_tag())]
        if method == "CANCEL":
            return [sip.build_response(req, 200)]
        return [sip.build_response(req, 501, "Not Implemented")]

    def _invite_responses(self, req: SIPMessage) -> list[SIPMessage]:
        to_tag = sip.new_tag()
        contact = f"<sip:{self.username}@{self.host}:{self.port}>"
        sdp = sip.generate_sdp(self.host, port=40000)
        return [
            sip.build_response(req, 100),
            sip.build_response(req, 180, to_tag=to_tag),
            sip.build_response(req, 200, to_tag=to_tag, contact=contact,
                               extra_headers={"Content-Type": "application/sdp"}, body=sdp),
        ]

    def _handle_auth(self, req: SIPMessage, challenge_code: int,
                     challenge_header: str) -> list[SIPMessage]:
        resp_header = "Authorization" if challenge_header == "WWW-Authenticate" else "Proxy-Authorization"
        auth = req.headers.get(resp_header)
        if not auth:
            www = (f'Digest realm="{REALM}", nonce="{self._nonce}", '
                   f'algorithm=MD5, qop="auth"')
            return [sip.build_response(req, challenge_code,
                                       to_tag=sip.new_tag(),
                                       extra_headers={challenge_header: www})]
        if self._verify_digest(auth, req.method or ""):
            return [sip.build_response(req, 200, to_tag=sip.new_tag(),
                                       extra_headers={"Expires": "3600"})]
        return [sip.build_response(req, 403, "Forbidden")]

    def _verify_digest(self, auth_value: str, method: str) -> bool:
        scheme, _, rest = auth_value.strip().partition(" ")
        if scheme.lower() != "digest":
            return False
        p = _parse_params(rest)
        if p.get("username") != self.username or p.get("nonce") != self._nonce:
            return False
        ha1 = hashlib.md5(f"{self.username}:{REALM}:{self.password}".encode()).hexdigest()
        ha2 = hashlib.md5(f"{method}:{p.get('uri', '')}".encode()).hexdigest()
        if p.get("qop") == "auth":
            expected = hashlib.md5(
                f"{ha1}:{self._nonce}:{p.get('nc','')}:{p.get('cnonce','')}:auth:{ha2}".encode()
            ).hexdigest()
        else:
            expected = hashlib.md5(f"{ha1}:{self._nonce}:{ha2}".encode()).hexdigest()
        return secrets.compare_digest(expected, p.get("response", ""))

    def _protocol_problem(self, req: SIPMessage) -> str | None:
        for h in ("Call-ID", "From", "To", "CSeq", "Via"):
            if h not in req.headers:
                return f"Missing {h}"
            if len(req.headers.get_all(h)) > 1 and h in ("From", "To", "Call-ID", "CSeq"):
                return f"Duplicate {h}"
        cseq = req.headers.get("CSeq", "")
        parts = cseq.split()
        if len(parts) != 2 or not parts[0].isdigit():
            return "Malformed CSeq"
        if parts[1].upper() != (req.method or "").upper():
            return "CSeq method mismatch"
        via = req.headers.get("Via", "")
        if "branch=" not in via:
            return "Via without branch"
        mf = req.headers.get("Max-Forwards")
        if mf is not None:
            try:
                if int(mf) < 0:
                    return "Negative Max-Forwards"
            except ValueError:
                return "Malformed Max-Forwards"
        return None


def run_background(**kwargs) -> TestSIPServer:
    """Start a server on a background thread and return it (call .stop())."""
    server = TestSIPServer(**kwargs)
    server.start()
    # Give the OS a moment to bind before the caller sends to it.
    time.sleep(0.05)
    return server
