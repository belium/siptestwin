"""Parser for a documented SIPp-compatible subset of scenario XML.

Supported elements: ``<scenario>``, ``<send>``, ``<recv>``, ``<pause>`` and,
inside ``<recv>``, ``<action><ereg .../></action>`` for safe field extraction.

Two ``<send>`` forms are supported:

* **Built-in** — ``<send request="OPTIONS"/>``: the engine constructs a
  well-formed request from the identity/target configuration.
* **Template** — ``<send>`` with a CDATA SIP message using ``[placeholders]``
  (SIPp style) for full control.

See ``docs/scenarios.md`` for the compatibility matrix. Parsing is hardened:
DOCTYPE / external entities are rejected, and regular expressions are length
limited to avoid pathological patterns.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from xml.etree import ElementTree as ET

MAX_SCENARIO_BYTES = 1_048_576  # 1 MiB
MAX_REGEX_LEN = 512


class ScenarioError(ValueError):
    """Raised for invalid or unsafe scenario documents."""


@dataclass
class Extract:
    """An ``<ereg>`` field-extraction action."""

    regexp: str
    assign_to: str
    search_in: str = "msg"   # "msg" | "hdr"
    header: str | None = None
    occurrence: int = 1

    def compile(self) -> re.Pattern[str]:
        if len(self.regexp) > MAX_REGEX_LEN:
            raise ScenarioError(f"regexp too long (>{MAX_REGEX_LEN} chars)")
        try:
            return re.compile(self.regexp)
        except re.error as exc:
            raise ScenarioError(f"invalid regexp {self.regexp!r}: {exc}") from exc


@dataclass
class Send:
    builtin_method: str | None = None
    template: str | None = None
    retrans_ms: int | None = None
    label: str | None = None
    # Per-send header/body parametrization (built-in form only):
    set_headers: dict[str, str] = field(default_factory=dict)
    remove_headers: list[str] = field(default_factory=list)
    body: str | None = None
    content_type: str | None = None

    @property
    def kind(self) -> str:
        return "send"


@dataclass
class Recv:
    response: int | None = None
    request: str | None = None
    optional: bool = False
    timeout_ms: int | None = None
    actions: list[Extract] = field(default_factory=list)
    label: str | None = None

    @property
    def kind(self) -> str:
        return "recv"


@dataclass
class Pause:
    milliseconds: int
    label: str | None = None

    @property
    def kind(self) -> str:
        return "pause"


Step = Send | Recv | Pause


@dataclass
class Scenario:
    name: str
    steps: list[Step]

    def summary(self) -> str:
        parts = []
        for s in self.steps:
            if isinstance(s, Send):
                parts.append(f"send({s.builtin_method or 'template'})")
            elif isinstance(s, Recv):
                tgt = s.response if s.response is not None else s.request
                parts.append(f"recv({tgt}{'?' if s.optional else ''})")
            else:
                parts.append(f"pause({s.milliseconds}ms)")
        return " -> ".join(parts)


def _guard_xml(text: str) -> None:
    lowered = text.lower()
    if "<!doctype" in lowered or "<!entity" in lowered:
        raise ScenarioError("DOCTYPE / entity declarations are not allowed in scenarios")


def _bool_attr(el: ET.Element, name: str, default: bool = False) -> bool:
    val = el.get(name)
    if val is None:
        return default
    return val.strip().lower() in ("true", "1", "yes")


def _int_attr(el: ET.Element, name: str) -> int | None:
    val = el.get(name)
    if val is None:
        return None
    try:
        return int(val)
    except ValueError as exc:
        raise ScenarioError(f"attribute {name!r} must be an integer, got {val!r}") from exc


def parse_string(text: str, *, name: str = "<string>") -> Scenario:
    if len(text.encode("utf-8")) > MAX_SCENARIO_BYTES:
        raise ScenarioError("scenario document exceeds size limit")
    _guard_xml(text)
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ScenarioError(f"XML parse error: {exc}") from exc
    if root.tag != "scenario":
        raise ScenarioError(f"root element must be <scenario>, got <{root.tag}>")

    scenario_name = root.get("name", name)
    steps: list[Step] = []
    for el in list(root):
        if el.tag == "send":
            steps.append(_parse_send(el))
        elif el.tag == "recv":
            steps.append(_parse_recv(el))
        elif el.tag == "pause":
            ms = _int_attr(el, "milliseconds")
            if ms is None:
                ms = _int_attr(el, "ms") or 0
            if ms < 0:
                raise ScenarioError("pause milliseconds must be >= 0")
            steps.append(Pause(milliseconds=ms, label=el.get("label")))
        elif el.tag in ("Reference", "nop"):
            continue  # tolerated no-ops
        elif el.tag in ("sendCmd", "recvCmd"):
            raise ScenarioError(
                f"<{el.tag}> (external command control) is not supported for safety"
            )
        else:
            raise ScenarioError(f"unsupported scenario element <{el.tag}>")

    if not steps:
        raise ScenarioError("scenario contains no steps")
    _validate_flow(steps)
    return Scenario(name=scenario_name, steps=steps)


def _parse_send(el: ET.Element) -> Send:
    method = el.get("request")
    children = [c for c in list(el) if isinstance(c.tag, str)]
    # Direct CDATA/text only counts as a template when there are no child
    # <header>/<body> elements (those belong to the built-in form).
    template = (el.text or "").strip() or None
    if children:
        template = None
    if method and (el.text or "").strip() and not children:
        raise ScenarioError("<send> cannot have both request= and a body template")
    if not method and not template:
        raise ScenarioError("<send> needs either request= or a CDATA template")
    if method:
        method = method.strip().upper()

    set_headers: dict[str, str] = {}
    remove_headers: list[str] = []
    body: str | None = None
    content_type: str | None = None
    for child in children:
        if child.tag == "header":
            name = child.get("name")
            if not name:
                raise ScenarioError("<header> requires a name attribute")
            action = (child.get("action") or "set").lower()
            if action == "remove":
                remove_headers.append(name)
            elif action == "set":
                set_headers[name] = (child.text or "").strip()
            else:
                raise ScenarioError(f"<header action> must be set|remove, got {action!r}")
        elif child.tag == "body":
            body = (child.text or "").strip()
            content_type = child.get("content-type") or child.get("content_type")
        else:
            raise ScenarioError(f"unsupported child <{child.tag}> inside <send>")

    if (set_headers or remove_headers or body is not None) and not method:
        raise ScenarioError("<header>/<body> require the built-in form (request=...)")

    return Send(
        builtin_method=method,
        template=template,
        retrans_ms=_int_attr(el, "retrans"),
        label=el.get("label"),
        set_headers=set_headers,
        remove_headers=remove_headers,
        body=body,
        content_type=content_type,
    )


def _parse_recv(el: ET.Element) -> Recv:
    response = _int_attr(el, "response")
    request = el.get("request")
    if response is None and not request:
        raise ScenarioError("<recv> needs response= or request=")
    if response is not None and not (100 <= response <= 699):
        raise ScenarioError(f"<recv response> must be 100-699, got {response}")
    actions: list[Extract] = []
    for action_el in el.findall("action"):
        for ereg in action_el.findall("ereg"):
            regexp = ereg.get("regexp")
            assign = ereg.get("assign_to") or ereg.get("variable")
            if not regexp or not assign:
                raise ScenarioError("<ereg> requires regexp and assign_to")
            actions.append(
                Extract(
                    regexp=regexp,
                    assign_to=assign.strip(),
                    search_in=ereg.get("search_in", "msg").lower(),
                    header=ereg.get("header"),
                    occurrence=_int_attr(ereg, "occurence") or 1,
                )
            )
    return Recv(
        response=response,
        request=request.strip().upper() if request else None,
        optional=_bool_attr(el, "optional"),
        timeout_ms=_int_attr(el, "timeout"),
        actions=actions,
        label=el.get("label"),
    )


def _validate_flow(steps: list[Step]) -> None:
    """Basic sanity checks on step ordering."""
    if not isinstance(steps[0], Send):
        raise ScenarioError("a UAC scenario must start with a <send>")


def parse_file(path: str | Path) -> Scenario:
    p = Path(path)
    if not p.is_file():
        raise ScenarioError(f"scenario file not found: {p}")
    return parse_string(p.read_text(encoding="utf-8"), name=p.name)
