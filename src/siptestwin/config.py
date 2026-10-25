"""Configuration model, loading and validation (YAML / JSON).

All operational parameters live in configuration so the tool never needs code
changes to run a different test. Validation is strict: types, ranges and
mutually incompatible options are checked, and the target must be explicit.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

import yaml

VALID_TRANSPORTS = {"udp", "tcp", "tls"}
VALID_AUTH = {"disabled", "digest"}
VALID_FORMATS = {"json", "csv"}

# Operational hard limits. These are ceilings the tool refuses to exceed even
# if a config asks for more, to keep tests controlled.
MAX_CALLS = 100_000
MAX_CONCURRENCY = 500
MAX_CALL_RATE = 500.0
MAX_DURATION = 86_400


class ConfigError(ValueError):
    """Raised when configuration is missing, malformed or out of range."""


@dataclass
class TargetConfig:
    host: str
    port: int = 5060
    transport: str = "udp"

    def validate(self, errors: list[str]) -> None:
        if not self.host or not isinstance(self.host, str):
            errors.append("target.host is required and must be a string")
        if not (0 < int(self.port) <= 65535):
            errors.append(f"target.port must be 1-65535, got {self.port}")
        if self.transport.lower() not in VALID_TRANSPORTS:
            errors.append(
                f"target.transport must be one of {sorted(VALID_TRANSPORTS)}, "
                f"got {self.transport!r}"
            )


@dataclass
class IdentityConfig:
    from_user: str = "tester"
    from_domain: str = "lab.example"
    to_user: str = "1001"
    to_domain: str | None = None     # defaults to target host
    contact_user: str = "tester"
    display_name: str | None = None

    def validate(self, errors: list[str]) -> None:
        for name in ("from_user", "to_user", "contact_user"):
            val = getattr(self, name)
            if not val or not isinstance(val, str):
                errors.append(f"identity.{name} must be a non-empty string")


@dataclass
class ExecutionConfig:
    scenario: str = ""
    calls: int = 1
    concurrency: int = 1
    call_rate: float = 1.0
    timeout_seconds: float = 5.0
    duration_seconds: float = 0.0   # 0 == bounded by calls, not time
    local_host: str | None = None   # Via/Contact host; autodetected if None
    local_port: int = 0             # 0 == OS-assigned ephemeral source port

    def validate(self, errors: list[str]) -> None:
        if not self.scenario:
            errors.append("execution.scenario is required")
        if not (1 <= int(self.calls) <= MAX_CALLS):
            errors.append(f"execution.calls must be 1-{MAX_CALLS}, got {self.calls}")
        if not (1 <= int(self.concurrency) <= MAX_CONCURRENCY):
            errors.append(
                f"execution.concurrency must be 1-{MAX_CONCURRENCY}, got {self.concurrency}"
            )
        if not (0 < float(self.call_rate) <= MAX_CALL_RATE):
            errors.append(
                f"execution.call_rate must be >0 and <= {MAX_CALL_RATE}, got {self.call_rate}"
            )
        if self.timeout_seconds <= 0:
            errors.append("execution.timeout_seconds must be > 0")
        if self.duration_seconds < 0 or self.duration_seconds > MAX_DURATION:
            errors.append(f"execution.duration_seconds must be 0-{MAX_DURATION}")
        if self.concurrency > self.calls:
            errors.append("execution.concurrency cannot exceed execution.calls")


@dataclass
class SecurityConfig:
    authentication: str = "disabled"
    username: str | None = None
    password: str | None = None
    verify_tls: bool = True
    authorized_targets: list[str] = field(default_factory=list)
    require_confirmation: bool = True

    def validate(self, errors: list[str]) -> None:
        if self.authentication.lower() not in VALID_AUTH:
            errors.append(
                f"security.authentication must be one of {sorted(VALID_AUTH)}, "
                f"got {self.authentication!r}"
            )
        if self.authentication.lower() == "digest" and not self.username:
            errors.append("security.authentication=digest requires security.username")


@dataclass
class ReportingConfig:
    output_dir: str = "results"
    formats: list[str] = field(default_factory=lambda: ["json"])

    def validate(self, errors: list[str]) -> None:
        for fmt in self.formats:
            if fmt.lower() not in VALID_FORMATS:
                errors.append(
                    f"reporting.formats entries must be in {sorted(VALID_FORMATS)}, "
                    f"got {fmt!r}"
                )


@dataclass
class InviteConfig:
    """INVITE-specific message customization."""

    content_type: str = "application/sdp"
    sdp: str | None = None            # custom SDP body (overrides the generated one)
    extra_headers: dict[str, str] = field(default_factory=dict)

    def validate(self, errors: list[str]) -> None:
        if not isinstance(self.extra_headers, dict):
            errors.append("message.invite.extra_headers must be a mapping")
        if self.sdp is not None and not isinstance(self.sdp, str):
            errors.append("message.invite.sdp must be a string")


@dataclass
class MessageConfig:
    """Global header / body parametrization applied to built-in requests.

    ``extra_headers`` are added to every built-in request; ``remove_headers``
    are stripped from them; ``invite`` customizes the INVITE body and headers.
    Header values support scenario placeholders (e.g. ``[call_id]``, ``[$var]``).
    """

    extra_headers: dict[str, str] = field(default_factory=dict)
    remove_headers: list[str] = field(default_factory=list)
    invite: InviteConfig = field(default_factory=InviteConfig)

    def validate(self, errors: list[str]) -> None:
        if not isinstance(self.extra_headers, dict):
            errors.append("message.extra_headers must be a mapping")
        if not isinstance(self.remove_headers, list):
            errors.append("message.remove_headers must be a list")
        self.invite.validate(errors)


@dataclass
class CaptureConfig:
    """SIP message tracing / capture options."""

    enabled: bool = False
    console: bool = False          # one line per message to the console
    console_full: bool = False     # also print the full message to the console
    text: bool = True              # write a human-readable .trace.log
    pcap: bool = False             # write a Wireshark-openable .pcap
    file: str | None = None        # base path; default <output_dir>/trace-<stamp>

    def validate(self, errors: list[str]) -> None:
        for name in ("enabled", "console", "console_full", "text", "pcap"):
            if not isinstance(getattr(self, name), bool):
                errors.append(f"capture.{name} must be a boolean")
        if self.enabled and not (self.console or self.text or self.pcap):
            errors.append("capture.enabled is true but no sink (console/text/pcap) is on")


@dataclass
class Config:
    target: TargetConfig
    identity: IdentityConfig = field(default_factory=IdentityConfig)
    execution: ExecutionConfig = field(default_factory=ExecutionConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    reporting: ReportingConfig = field(default_factory=ReportingConfig)
    message: MessageConfig = field(default_factory=MessageConfig)
    capture: CaptureConfig = field(default_factory=CaptureConfig)
    source_path: str | None = None

    def validate(self) -> list[str]:
        errors: list[str] = []
        self.target.validate(errors)
        self.identity.validate(errors)
        self.execution.validate(errors)
        self.security.validate(errors)
        self.reporting.validate(errors)
        self.message.validate(errors)
        self.capture.validate(errors)
        # TLS verification only meaningful with TLS transport.
        if self.target.transport.lower() != "tls" and not self.security.verify_tls:
            # not an error, but normalize silently
            pass
        return errors

    def validate_or_raise(self) -> "Config":
        errors = self.validate()
        if errors:
            raise ConfigError("Invalid configuration:\n  - " + "\n  - ".join(errors))
        return self


def _section(data: dict[str, Any], key: str) -> dict[str, Any]:
    value = data.get(key, {})
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ConfigError(f"config section {key!r} must be a mapping")
    return value


def _only_known(cls: type, data: dict[str, Any]) -> dict[str, Any]:
    known = {f.name for f in fields(cls)}
    unknown = set(data) - known
    if unknown:
        raise ConfigError(f"unknown keys in {cls.__name__}: {sorted(unknown)}")
    return data


def from_dict(data: dict[str, Any], *, source_path: str | None = None) -> Config:
    if not isinstance(data, dict):
        raise ConfigError("top-level configuration must be a mapping")
    if "target" not in data:
        raise ConfigError("configuration must define a 'target' section")

    target = TargetConfig(**_only_known(TargetConfig, _section(data, "target")))
    identity = IdentityConfig(**_only_known(IdentityConfig, _section(data, "identity")))
    execution = ExecutionConfig(**_only_known(ExecutionConfig, _section(data, "execution")))
    security = SecurityConfig(**_only_known(SecurityConfig, _section(data, "security")))
    reporting = ReportingConfig(**_only_known(ReportingConfig, _section(data, "reporting")))
    message = _message(_section(data, "message"))
    capture = CaptureConfig(**_only_known(CaptureConfig, _section(data, "capture")))
    return Config(
        target=target,
        identity=identity,
        execution=execution,
        security=security,
        reporting=reporting,
        message=message,
        capture=capture,
        source_path=source_path,
    )


def _message(data: dict[str, Any]) -> MessageConfig:
    invite_data = data.get("invite", {}) or {}
    if not isinstance(invite_data, dict):
        raise ConfigError("message.invite must be a mapping")
    invite = InviteConfig(**_only_known(InviteConfig, invite_data))
    top = {k: v for k, v in data.items() if k != "invite"}
    _only_known(MessageConfig, top)  # reject unknown top-level message keys
    return MessageConfig(invite=invite, **top)


def load(path: str | os.PathLike[str]) -> Config:
    """Load and parse a YAML or JSON config file (no validation)."""
    p = Path(path)
    if not p.is_file():
        raise ConfigError(f"config file not found: {p}")
    raw = p.read_text(encoding="utf-8")
    if p.suffix.lower() in (".yaml", ".yml"):
        data = yaml.safe_load(raw)
    elif p.suffix.lower() == ".json":
        data = json.loads(raw)
    else:
        # Try YAML first (superset of JSON), fall back to JSON.
        try:
            data = yaml.safe_load(raw)
        except yaml.YAMLError:
            data = json.loads(raw)
    return from_dict(data or {}, source_path=str(p))


def load_and_validate(path: str | os.PathLike[str]) -> Config:
    return load(path).validate_or_raise()
