"""SIP transaction state machine (RFC 3261 section 17).

A SIP *transaction* is the exchange of a single request and its responses,
matched by the Via branch parameter and the CSeq method. This is distinct from
a *dialog* / call session (see :mod:`siptestwin.dialog`): one dialog can span
several transactions (INVITE, then BYE, etc.).

This module implements the client-side transaction timers and state handling
used by the test engine (UAC). Server transaction handling lives in the test
server. Timers follow RFC 3261 defaults and apply retransmissions only on
unreliable (UDP) transports.
"""

from __future__ import annotations

import enum
import time
from dataclasses import dataclass, field

from .sip_message import SIPMessage

# RFC 3261 timer defaults (seconds).
T1 = 0.5
T2 = 4.0
T4 = 5.0
TIMER_B = 64 * T1   # INVITE client transaction timeout
TIMER_F = 64 * T1   # non-INVITE client transaction timeout
TIMER_D = 32.0      # wait in Completed (INVITE, UDP)
TIMER_K = T4        # wait in Completed (non-INVITE, UDP)


class TxState(enum.Enum):
    CALLING = "calling"        # INVITE only
    TRYING = "trying"          # non-INVITE only
    PROCEEDING = "proceeding"
    COMPLETED = "completed"
    TERMINATED = "terminated"


@dataclass
class ClientTransaction:
    """Tracks one outgoing request and the matching responses."""

    request: SIPMessage
    branch: str
    method: str
    reliable: bool
    created_at: float = field(default_factory=time.monotonic)
    state: TxState = field(init=False)
    last_response: SIPMessage | None = None
    responses: list[SIPMessage] = field(default_factory=list)
    retransmit_count: int = 0
    _next_interval: float = T1
    _last_tx_at: float = field(default_factory=time.monotonic)

    def __post_init__(self) -> None:
        self.state = TxState.CALLING if self.is_invite else TxState.TRYING

    @property
    def is_invite(self) -> bool:
        return self.method == "INVITE"

    # ----- matching -------------------------------------------------------
    def matches(self, response: SIPMessage) -> bool:
        """RFC 3261 section 17.1.3 transaction matching (client side)."""
        if not response.is_response:
            return False
        if response.top_via_branch() != self.branch:
            return False
        rmethod = response.cseq_method
        # CANCEL and INVITE share a branch but are different transactions.
        return rmethod == self.method

    # ----- events ---------------------------------------------------------
    def on_response(self, response: SIPMessage) -> None:
        """Advance the state machine for a received response."""
        self.last_response = response
        self.responses.append(response)
        code = response.status_code or 0
        if self.is_invite:
            if code < 200:
                self.state = TxState.PROCEEDING
            elif 200 <= code < 300:
                # 2xx terminates the INVITE client transaction immediately;
                # ACK for 2xx is a separate transaction handled by the dialog.
                self.state = TxState.TERMINATED
            else:
                self.state = TxState.COMPLETED  # must ACK the failure response
        else:
            if code < 200:
                self.state = TxState.PROCEEDING
            else:
                self.state = TxState.COMPLETED

    # ----- retransmission (UDP only) -------------------------------------
    def due_for_retransmit(self, now: float) -> bool:
        if self.reliable:
            return False
        if self.state not in (TxState.CALLING, TxState.TRYING, TxState.PROCEEDING):
            return False
        # Non-INVITE stops retransmitting once provisional received.
        if not self.is_invite and self.state == TxState.PROCEEDING:
            return False
        return (now - self._last_tx_at) >= self._next_interval

    def note_retransmit(self, now: float) -> None:
        self.retransmit_count += 1
        self._last_tx_at = now
        if self.is_invite:
            # INVITE: interval doubles each time (T1, 2T1, 4T1, ...).
            self._next_interval = min(self._next_interval * 2, TIMER_B)
        else:
            # non-INVITE: double up to T2, then cap at T2.
            self._next_interval = min(self._next_interval * 2, T2)

    def timed_out(self, now: float) -> bool:
        if self.state in (TxState.COMPLETED, TxState.TERMINATED):
            return False
        limit = TIMER_B if self.is_invite else TIMER_F
        return (now - self.created_at) >= limit

    @property
    def is_done(self) -> bool:
        return self.state in (TxState.COMPLETED, TxState.TERMINATED)
