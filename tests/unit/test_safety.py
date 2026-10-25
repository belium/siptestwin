import pytest

from siptestwin import config as cfg
from siptestwin import safety


def _config(targets):
    return cfg.from_dict({
        "target": {"host": "192.0.2.10", "port": 5060, "transport": "udp"},
        "execution": {"scenario": "s", "calls": 1, "concurrency": 1, "call_rate": 1},
        "security": {"authorized_targets": targets},
    })


def test_empty_allowlist_authorizes_nothing():
    assert not safety.is_authorized("192.0.2.10", [])


def test_exact_ip_match():
    assert safety.is_authorized("192.0.2.10", ["192.0.2.10"])


def test_cidr_match():
    assert safety.is_authorized("192.0.2.10", ["192.0.2.0/24"])
    assert not safety.is_authorized("198.51.100.1", ["192.0.2.0/24"])


def test_ensure_authorized_raises_when_absent():
    with pytest.raises(safety.AuthorizationError):
        safety.ensure_authorized(_config([]))


def test_ensure_authorized_ok_when_listed():
    safety.ensure_authorized(_config(["192.0.2.0/24"]))  # no raise


def test_redaction_removes_credentials():
    text = ("Authorization: Digest username=\"u\", response=\"deadbeef\"\r\n"
            "WWW-Authenticate: Digest response=\"abc123\"")
    red = safety.redact(text)
    assert "deadbeef" not in red
    assert "abc123" not in red
    assert "<redacted>" in red
