"""Metrics collection: counters, latency percentiles and failure reasons.

Local generator errors (timeouts, transport failures, scenario assertion
failures) are tracked separately from server-reported SIP failures so reports
can distinguish "the server rejected us" from "our test runner had a problem".
"""

from __future__ import annotations

import threading
from collections import Counter
from dataclasses import dataclass, field


def _percentile(sorted_values: list[float], pct: float) -> float:
    if not sorted_values:
        return 0.0
    if len(sorted_values) == 1:
        return sorted_values[0]
    rank = (pct / 100.0) * (len(sorted_values) - 1)
    lo = int(rank)
    hi = min(lo + 1, len(sorted_values) - 1)
    frac = rank - lo
    return sorted_values[lo] + (sorted_values[hi] - sorted_values[lo]) * frac


@dataclass
class Metrics:
    """Thread-safe aggregate metrics for a run."""

    messages_sent: int = 0
    messages_received: int = 0
    retransmissions: int = 0
    transport_errors: int = 0
    timeouts: int = 0

    calls_attempted: int = 0
    calls_established: int = 0
    calls_terminated: int = 0

    transactions_completed: int = 0
    transactions_failed: int = 0

    response_codes: Counter = field(default_factory=Counter)
    failure_reasons: Counter = field(default_factory=Counter)
    _latencies_ms: list[float] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    # ----- increments -----------------------------------------------------
    def sent(self, n: int = 1) -> None:
        with self._lock:
            self.messages_sent += n

    def received(self, code: int | None = None) -> None:
        with self._lock:
            self.messages_received += 1
            if code is not None:
                self.response_codes[code] += 1

    def retransmit(self) -> None:
        with self._lock:
            self.retransmissions += 1

    def transport_error(self) -> None:
        with self._lock:
            self.transport_errors += 1

    def timeout(self) -> None:
        with self._lock:
            self.timeouts += 1

    def latency(self, ms: float) -> None:
        with self._lock:
            self._latencies_ms.append(ms)

    def call_attempt(self) -> None:
        with self._lock:
            self.calls_attempted += 1

    def call_established(self) -> None:
        with self._lock:
            self.calls_established += 1

    def call_terminated(self) -> None:
        with self._lock:
            self.calls_terminated += 1

    def transaction_result(self, ok: bool, reason: str | None = None) -> None:
        with self._lock:
            if ok:
                self.transactions_completed += 1
            else:
                self.transactions_failed += 1
                if reason:
                    self.failure_reasons[reason] += 1

    # ----- derived --------------------------------------------------------
    def latency_percentiles(self) -> dict[str, float]:
        with self._lock:
            vals = sorted(self._latencies_ms)
        return {
            "count": len(vals),
            "min_ms": round(vals[0], 2) if vals else 0.0,
            "p50_ms": round(_percentile(vals, 50), 2),
            "p95_ms": round(_percentile(vals, 95), 2),
            "p99_ms": round(_percentile(vals, 99), 2),
            "max_ms": round(vals[-1], 2) if vals else 0.0,
        }

    def response_by_category(self) -> dict[str, int]:
        cats: Counter = Counter()
        with self._lock:
            for code, n in self.response_codes.items():
                cats[f"{code // 100}xx"] += n
        return dict(sorted(cats.items()))

    def to_dict(self) -> dict:
        return {
            "messages_sent": self.messages_sent,
            "messages_received": self.messages_received,
            "retransmissions": self.retransmissions,
            "transport_errors": self.transport_errors,
            "timeouts": self.timeouts,
            "calls_attempted": self.calls_attempted,
            "calls_established": self.calls_established,
            "calls_terminated": self.calls_terminated,
            "transactions_completed": self.transactions_completed,
            "transactions_failed": self.transactions_failed,
            "response_codes": {str(k): v for k, v in sorted(self.response_codes.items())},
            "response_by_category": self.response_by_category(),
            "failure_reasons": dict(self.failure_reasons),
            "latency": self.latency_percentiles(),
        }
