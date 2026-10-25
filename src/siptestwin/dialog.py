"""SIP dialog / call session state (RFC 3261 section 12).

A dialog is a peer-to-peer relationship identified by Call-ID plus the local
and remote tags. It persists across the transactions of a call (INVITE ->
200 -> ACK ... BYE). This holds the state needed to build in-dialog requests
(ACK, BYE) with correct tags, CSeq and target.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import sip_message as sip
from .sip_message import SIPMessage


@dataclass
class Dialog:
    call_id: str
    local_uri: str
    remote_uri: str
    local_tag: str
    remote_tag: str | None = None
    local_seq: int = 1
    remote_target: str | None = None   # Contact URI from the peer
    route_set: list[str] = field(default_factory=list)
    secure: bool = False
    confirmed: bool = False

    @classmethod
    def from_invite_response(
        cls,
        request: SIPMessage,
        response: SIPMessage,
        *,
        local_uri: str,
        remote_uri: str,
    ) -> "Dialog":
        """Create a dialog from an INVITE and its dialog-establishing response."""
        d = cls(
            call_id=request.call_id or "",
            local_uri=local_uri,
            remote_uri=remote_uri,
            local_tag=request.from_tag() or sip.new_tag(),
            remote_tag=response.to_tag(),
            local_seq=request.cseq_number or 1,
        )
        contact = response.headers.get("Contact")
        if contact:
            d.remote_target = _uri_from_contact(contact)
        # Record-Route set (reversed) would populate route_set; omitted for the
        # direct UAC<->UAS lab topology this tool targets.
        d.confirmed = bool(response.status_code and response.status_code >= 200)
        return d

    def _target_uri(self) -> str:
        return self.remote_target or self.remote_uri

    def build_ack(self, invite: SIPMessage, response: SIPMessage,
                  via_host: str, via_port: int, transport: str) -> SIPMessage:
        """Build an ACK for a 2xx response (new transaction, same CSeq num)."""
        ack = sip.build_request(
            "ACK",
            self._target_uri(),
            from_uri=self.local_uri,
            to_uri=self.remote_uri,
            call_id=self.call_id,
            cseq=invite.cseq_number or self.local_seq,
            via_host=via_host,
            via_port=via_port,
            transport=transport,
            from_tag=self.local_tag,
            to_tag=self.remote_tag,
        )
        return ack

    def build_bye(self, via_host: str, via_port: int, transport: str) -> SIPMessage:
        """Build a BYE to tear down a confirmed dialog (new transaction)."""
        self.local_seq += 1
        return sip.build_request(
            "BYE",
            self._target_uri(),
            from_uri=self.local_uri,
            to_uri=self.remote_uri,
            call_id=self.call_id,
            cseq=self.local_seq,
            via_host=via_host,
            via_port=via_port,
            transport=transport,
            from_tag=self.local_tag,
            to_tag=self.remote_tag,
        )


def _uri_from_contact(contact: str) -> str:
    """Extract the SIP URI from a Contact header value (strip display + <>)."""
    value = contact.strip()
    if "<" in value and ">" in value:
        return value[value.index("<") + 1: value.index(">")]
    return value.split(";")[0].strip()
