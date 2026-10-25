"""Safety controls for SIPTestWin.

These controls exist to keep the tool usable only against systems the operator
owns or is explicitly authorized to test, and to keep every test bounded:

* an explicit allow-list of authorized targets (no implicit "private IP ==
  allowed" assumption);
* rate / concurrency / duration ceilings enforced on top of config limits;
* a validation-only (dry-run) mode that transmits no packets;
* explicit operator confirmation before any active (packet-sending) test;
* credential redaction so passwords never reach logs or reports;
* an append-only audit log of every active run.

The tool deliberately has no functionality for credential brute-forcing,
unbounded flooding, toll fraud, or automated exploitation of third parties.
"""

from __future__ import annotations

import ipaddress
import json
import re
import socket
import time
from dataclasses import dataclass
from pathlib import Path

from .config import Config

# Values that must never appear verbatim in logs/reports.
_SECRET_KEYS = ("password", "passwd", "secret", "response=", "authorization")
_AUTH_LINE = re.compile(r"(?im)^(Proxy-)?Authorization:.*$")
_WWW_RESP = re.compile(r'(response=")[^"]*(")')


class AuthorizationError(RuntimeError):
    """Raised when a target is not on the authorized allow-list."""


class ConfirmationRequired(RuntimeError):
    """Raised when an active test is attempted without confirmation."""


def redact(text: str) -> str:
    """Remove credential material from a text blob (for logs/reports)."""
    text = _AUTH_LINE.sub(lambda m: m.group(0).split(":", 1)[0] + ": <redacted>", text)
    text = _WWW_RESP.sub(r'\1<redacted>\2', text)
    return text


def redact_config(config: Config) -> dict:
    """Return a dict view of ``config`` safe to log (password removed)."""
    return {
        "target": vars(config.target),
        "identity": vars(config.identity),
        "execution": vars(config.execution),
        "security": {
            **{k: v for k, v in vars(config.security).items() if k != "password"},
            "password": "<redacted>" if config.security.password else None,
        },
        "reporting": vars(config.reporting),
    }


def _normalize_host(host: str) -> set[str]:
    """Return candidate string forms for ``host`` (name and resolved IPs)."""
    forms = {host.lower()}
    try:
        forms.add(str(ipaddress.ip_address(host)))
    except ValueError:
        try:
            for info in socket.getaddrinfo(host, None):
                forms.add(info[4][0])
        except (socket.gaierror, OSError):
            pass
    return forms


def is_authorized(host: str, authorized_targets: list[str]) -> bool:
    """Check whether ``host`` matches the allow-list.

    Each allow-list entry is a hostname, an IP, or a CIDR network. Matching is
    exact for names and membership-based for networks. There is no implicit
    authorization: an empty allow-list authorizes nothing.
    """
    if not authorized_targets:
        return False
    candidates = _normalize_host(host)
    for entry in authorized_targets:
        entry = entry.strip()
        if not entry:
            continue
        if entry.lower() in candidates:
            return True
        try:
            net = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            continue
        for cand in candidates:
            try:
                if ipaddress.ip_address(cand) in net:
                    return True
            except ValueError:
                continue
    return False


def ensure_authorized(config: Config) -> None:
    """Raise :class:`AuthorizationError` if the target is not allow-listed."""
    host = config.target.host
    if not is_authorized(host, config.security.authorized_targets):
        raise AuthorizationError(
            f"target {host!r} is not in security.authorized_targets. "
            "Add it explicitly to confirm you own or are authorized to test it. "
            "A private IP address is NOT treated as authorization."
        )


@dataclass
class RunLimits:
    """Effective ceilings applied to a run (min of config and hard limits)."""

    calls: int
    concurrency: int
    call_rate: float
    duration_seconds: float

    @classmethod
    def from_config(cls, config: Config) -> "RunLimits":
        from .config import MAX_CALLS, MAX_CONCURRENCY, MAX_CALL_RATE, MAX_DURATION
        ex = config.execution
        return cls(
            calls=min(int(ex.calls), MAX_CALLS),
            concurrency=min(int(ex.concurrency), MAX_CONCURRENCY),
            call_rate=min(float(ex.call_rate), MAX_CALL_RATE),
            duration_seconds=min(float(ex.duration_seconds), MAX_DURATION),
        )


def confirmation_prompt(config: Config, limits: RunLimits) -> str:
    """Human-readable summary shown before an active test begins."""
    t = config.target
    return (
        "ACTIVE SIP TEST — packets WILL be transmitted\n"
        f"  target     : {t.host}:{t.port} ({t.transport.upper()})\n"
        f"  scenario   : {config.execution.scenario}\n"
        f"  calls      : {limits.calls}\n"
        f"  concurrency: {limits.concurrency}\n"
        f"  call_rate  : {limits.call_rate}/s\n"
        f"  duration   : {limits.duration_seconds or 'bounded by calls'}\n"
        f"  auth       : {config.security.authentication}\n"
    )


class AuditLog:
    """Append-only JSON-lines audit log of active runs."""

    def __init__(self, output_dir: str | Path) -> None:
        self.path = Path(output_dir) / "audit.log"

    def record(self, event: str, config: Config, extra: dict | None = None) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "event": event,
            "target": f"{config.target.host}:{config.target.port}/{config.target.transport}",
            "scenario": config.execution.scenario,
        }
        if extra:
            entry.update(extra)
        line = json.dumps(entry, ensure_ascii=False)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(redact(line) + "\n")
