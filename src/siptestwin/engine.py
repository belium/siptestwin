"""Scenario execution engine (UAC).

Drives a parsed scenario against the configured target: builds SIP requests,
sends them over the selected transport, matches responses to transactions,
handles Digest authentication, maintains the call dialog for ACK/BYE, performs
retransmissions on UDP, and records metrics and per-call outcomes.

Concurrency: a single shared transport is used; inbound messages are routed to
the owning call by Call-ID. Calls are paced by ``call_rate`` and limited by
``concurrency``.
"""

from __future__ import annotations

import queue
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from . import sip_message as sip
from .authentication import build_authorization, parse_challenge
from .config import Config
from .dialog import Dialog
from .metrics import Metrics
from .reporting import CallRecord, RunResult
from .safety import RunLimits
from .scenario_parser import Pause, Recv, Scenario, Send
from .sip_message import SIPMessage
from .transaction import ClientTransaction, T1
from .transport import Transport, TransportError, create_transport


class ScenarioAssertionError(RuntimeError):
    """Raised when a received message does not satisfy a recv expectation."""


def _detect_local_ip(target_host: str, target_port: int) -> str:
    """Best-effort local source IP for Via/Contact, without sending data."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect((target_host, target_port or 5060))
            return s.getsockname()[0]
        finally:
            s.close()
    except OSError:
        return "127.0.0.1"


@dataclass
class CallContext:
    index: int
    call_id: str
    from_tag: str
    inbox: "queue.Queue[SIPMessage]" = field(default_factory=queue.Queue)
    variables: dict[str, str] = field(default_factory=dict)
    cseq: int = 1
    last_request: SIPMessage | None = None
    last_invite: SIPMessage | None = None
    last_invite_response: SIPMessage | None = None
    dialog: Dialog | None = None
    current_tx: ClientTransaction | None = None
    auth_retried: bool = False
    steps_completed: int = 0


class Engine:
    def __init__(
        self,
        config: Config,
        scenario: Scenario,
        *,
        simulate: bool = False,
        metrics: Metrics | None = None,
        on_log=None,
        tracer=None,
    ) -> None:
        self.config = config
        self.scenario = scenario
        self.simulate = simulate
        self.metrics = metrics or Metrics()
        self.on_log = on_log or (lambda msg: None)
        self.tracer = tracer
        self.limits = RunLimits.from_config(config)

        ex = config.execution
        self.local_ip = ex.local_host or _detect_local_ip(config.target.host, config.target.port)
        self.local_port = ex.local_port
        self.transport_name = config.target.transport.lower()
        self.target_addr = (config.target.host, int(config.target.port))

        self._transport: Transport | None = None
        self._inboxes: dict[str, "queue.Queue[SIPMessage]"] = {}
        self._inbox_lock = threading.Lock()
        self._stop = threading.Event()

    # ----- lifecycle ------------------------------------------------------
    def run(self) -> RunResult:
        result = RunResult(
            target=f"{self.config.target.host}:{self.config.target.port}",
            scenario=self.scenario.name,
            transport=self.transport_name,
            simulate=self.simulate,
            started_at=time.time(),
            metrics=self.metrics,
        )
        if not self.simulate:
            self._start_transport()
        if self.tracer is not None:
            try:
                target_ip = socket.gethostbyname(self.config.target.host)
            except OSError:
                target_ip = self.config.target.host
            self.tracer.bind(self.local_ip, self.local_port, target_ip, self.transport_name)
        try:
            self._dispatch_calls(result)
        finally:
            self.local_port = self._bound_port()
            if self._transport is not None:
                self._transport.close()
            result.finished_at = time.time()
        return result

    def stop(self) -> None:
        self._stop.set()

    def _bound_port(self) -> int:
        if self._transport is not None:
            try:
                return self._transport.local_addr()[1]
            except Exception:
                return self.local_port
        return self.local_port

    def _start_transport(self) -> None:
        self._transport = create_transport(
            self.transport_name,
            peer=self.target_addr,
            bind_host="0.0.0.0",
            bind_port=self.local_port,
            verify_tls=self.config.security.verify_tls,
        )
        self._transport.start(self._on_inbound)
        self.local_port = self._transport.local_addr()[1]

    def _on_inbound(self, data: bytes, addr: tuple[str, int]) -> None:
        if self.tracer is not None:
            self.tracer.record("recv", data, addr)
        try:
            msg = sip.parse(data)
        except sip.SIPParseError:
            return
        call_id = msg.call_id
        if not call_id:
            return
        with self._inbox_lock:
            inbox = self._inboxes.get(call_id)
        if inbox is not None:
            inbox.put(msg)

    # ----- call scheduling ------------------------------------------------
    def _dispatch_calls(self, result: RunResult) -> None:
        total = self.limits.calls
        rate = self.limits.call_rate
        interval = 1.0 / rate if rate > 0 else 0.0
        deadline = (time.time() + self.limits.duration_seconds) if self.limits.duration_seconds else None
        records: list[CallRecord] = [None] * total  # type: ignore[list-item]

        with ThreadPoolExecutor(max_workers=self.limits.concurrency) as pool:
            futures = {}
            for i in range(total):
                if self._stop.is_set():
                    break
                if deadline and time.time() >= deadline:
                    break
                ctx = CallContext(
                    index=i,
                    call_id=sip.new_call_id(self.local_ip),
                    from_tag=sip.new_tag(),
                )
                with self._inbox_lock:
                    self._inboxes[ctx.call_id] = ctx.inbox
                futures[pool.submit(self._run_scenario, ctx)] = ctx
                if interval and i < total - 1:
                    time.sleep(interval)
            for fut, ctx in futures.items():
                try:
                    records[ctx.index] = fut.result()
                except Exception as exc:  # defensive: never lose a record
                    records[ctx.index] = CallRecord(
                        index=ctx.index, outcome="error", reason=str(exc)
                    )
                finally:
                    with self._inbox_lock:
                        self._inboxes.pop(ctx.call_id, None)

        result.calls = [r for r in records if r is not None]

    # ----- scenario execution --------------------------------------------
    def _run_scenario(self, ctx: CallContext) -> CallRecord:
        self.metrics.call_attempt()
        start = time.monotonic()
        final_code: int | None = None
        try:
            for step in self.scenario.steps:
                if self._stop.is_set():
                    raise ScenarioAssertionError("run stopped")
                if isinstance(step, Send):
                    self._do_send(ctx, step)
                elif isinstance(step, Recv):
                    code = self._do_recv(ctx, step)
                    if code is not None:
                        final_code = code
                elif isinstance(step, Pause):
                    self._do_pause(step)
                ctx.steps_completed += 1
            self.metrics.transaction_result(True)
            latency = (time.monotonic() - start) * 1000.0
            return CallRecord(
                index=ctx.index, outcome="passed", final_code=final_code,
                latency_ms=round(latency, 2), steps_completed=ctx.steps_completed,
            )
        except TimeoutError as exc:
            self.metrics.timeout()
            self.metrics.transaction_result(False, "timeout")
            return CallRecord(index=ctx.index, outcome="timeout", reason=str(exc),
                              final_code=final_code, steps_completed=ctx.steps_completed)
        except TransportError as exc:
            self.metrics.transport_error()
            self.metrics.transaction_result(False, "transport_error")
            return CallRecord(index=ctx.index, outcome="error", reason=str(exc),
                              final_code=final_code, steps_completed=ctx.steps_completed)
        except ScenarioAssertionError as exc:
            self.metrics.transaction_result(False, f"assertion:{exc}")
            return CallRecord(index=ctx.index, outcome="failed", reason=str(exc),
                              final_code=final_code, steps_completed=ctx.steps_completed)

    # ----- steps ----------------------------------------------------------
    def _do_pause(self, step: Pause) -> None:
        if self.simulate:
            return
        # Cap any single pause so Ctrl+C stays responsive.
        remaining = step.milliseconds / 1000.0
        while remaining > 0 and not self._stop.is_set():
            chunk = min(remaining, 0.25)
            time.sleep(chunk)
            remaining -= chunk

    def _do_send(self, ctx: CallContext, step: Send) -> None:
        msg = self._build_message(ctx, step)
        ctx.last_request = msg
        if msg.method == "INVITE":
            ctx.last_invite = msg
            self.metrics.call_attempt  # noqa: B018 (attempt counted per scenario)
        branch = msg.top_via_branch() or sip.new_branch()
        reliable = self.transport_name in ("tcp", "tls")
        if msg.method not in ("ACK",):
            ctx.current_tx = ClientTransaction(
                request=msg, branch=branch, method=msg.method or "", reliable=reliable
            )
        self.on_log(f"[call {ctx.index}] >> {msg.method} {msg.request_uri}")
        if self.simulate:
            if self.tracer is not None:
                self.tracer.record("sent", msg.serialize(), self.target_addr)
            self.metrics.sent()
            return
        self._transmit(ctx, msg)

    def _transmit(self, ctx: CallContext, msg: SIPMessage) -> None:
        assert self._transport is not None
        data = msg.serialize()
        if self.tracer is not None:
            self.tracer.record("sent", data, self.target_addr)
        self._transport.send(data, self.target_addr)
        self.metrics.sent()

    def _do_recv(self, ctx: CallContext, step: Recv) -> int | None:
        if self.simulate:
            # Nothing is transmitted in simulate mode; treat as satisfied.
            return step.response
        timeout_s = (step.timeout_ms / 1000.0) if step.timeout_ms else self.config.execution.timeout_seconds
        deadline = time.monotonic() + timeout_s
        tx = ctx.current_tx

        while True:
            now = time.monotonic()
            if now >= deadline:
                if step.optional:
                    return None
                raise TimeoutError(
                    f"timed out waiting for {step.response or step.request} "
                    f"(call {ctx.index})"
                )
            # UDP retransmission while waiting.
            if tx is not None and tx.due_for_retransmit(now):
                self._transmit(ctx, tx.request)
                tx.note_retransmit(now)
                self.metrics.retransmit()

            try:
                msg = ctx.inbox.get(timeout=min(T1, max(0.0, deadline - now)))
            except queue.Empty:
                continue

            self.metrics.received(msg.status_code)
            if tx is not None and tx.matches(msg):
                tx.on_response(msg)

            code = msg.status_code or 0
            # Automatic Digest authentication. When a 401/407 arrives and auth
            # is enabled, answer the challenge with the configured credentials
            # and send the authenticated retry. If the scenario explicitly
            # expects the challenge code, this step is satisfied by it and the
            # authenticated response is matched by the following recv; otherwise
            # we keep waiting on this step for the post-auth code.
            if (
                msg.is_response
                and code in (401, 407)
                and self._auth_enabled()
                and not ctx.auth_retried
            ):
                self._auth_retry(ctx, msg)
                tx = ctx.current_tx
                deadline = time.monotonic() + timeout_s
                if step.response == code:
                    self._run_extractions(ctx, step, msg)
                    return code
                continue

            matched = self._message_matches(step, msg)
            if not matched:
                # Provisional/unrelated responses are expected noise while we
                # wait for the matching message; keep waiting.
                continue

            self._run_extractions(ctx, step, msg)

            if msg.is_response:
                if msg.method == "INVITE" or (ctx.last_invite and msg.cseq_method == "INVITE"):
                    self._handle_invite_response(ctx, msg)
                return code
            return None

    def _message_matches(self, step: Recv, msg: SIPMessage) -> bool:
        if step.response is not None:
            return msg.is_response and msg.status_code == step.response
        if step.request is not None:
            return msg.is_request and (msg.method or "").upper() == step.request
        return False

    def _handle_invite_response(self, ctx: CallContext, resp: SIPMessage) -> None:
        code = resp.status_code or 0
        if code >= 200 and code < 300 and ctx.last_invite is not None:
            ctx.last_invite_response = resp
            ctx.dialog = Dialog.from_invite_response(
                ctx.last_invite, resp,
                local_uri=self._from_uri(ctx),
                remote_uri=self._to_uri(),
            )
            self.metrics.call_established()

    # ----- message construction ------------------------------------------
    def _from_uri(self, ctx: CallContext) -> str:
        ident = self.config.identity
        uri = f"sip:{ident.from_user}@{ident.from_domain}"
        if ident.display_name:
            return f'"{ident.display_name}" <{uri}>'
        return f"<{uri}>"

    def _to_uri(self) -> str:
        ident = self.config.identity
        domain = ident.to_domain or self.config.target.host
        return f"<sip:{ident.to_user}@{domain}>"

    def _contact(self) -> str:
        ident = self.config.identity
        return f"<sip:{ident.contact_user}@{self.local_ip}:{self.local_port or 5060};transport={self.transport_name}>"

    def _request_uri(self, method: str) -> str:
        ident = self.config.identity
        host = self.config.target.host
        if method == "REGISTER":
            return f"sip:{host}"
        domain = ident.to_domain or host
        return f"sip:{ident.to_user}@{domain}"

    def _build_message(self, ctx: CallContext, step: Send) -> SIPMessage:
        if step.template is not None:
            return self._build_from_template(ctx, step.template)
        method = step.builtin_method or ""
        if method == "ACK":
            return self._build_ack(ctx)
        if method == "BYE":
            return self._build_bye(ctx)
        return self._build_builtin(ctx, method, step)

    def _build_builtin(self, ctx: CallContext, method: str, step: Send | None = None) -> SIPMessage:
        mc = self.config.message
        extra: dict[str, str] = {}
        if method in ("INVITE", "REGISTER", "SUBSCRIBE", "OPTIONS"):
            extra["Allow"] = "INVITE, ACK, CANCEL, OPTIONS, BYE"
        if method == "REGISTER":
            extra["Expires"] = "3600"

        # Body resolution: scenario <body> > config message.invite.sdp >
        # generated SDP (INVITE only). Any method may carry a custom body.
        body, content_type = self._resolve_body(ctx, method, step)
        if content_type:
            extra["Content-Type"] = content_type

        contact = self._contact() if method in ("INVITE", "REGISTER", "SUBSCRIBE") else None
        msg = sip.build_request(
            method,
            self._request_uri(method),
            from_uri=self._from_uri(ctx),
            to_uri=self._to_uri() if method != "REGISTER" else self._from_uri(ctx),
            call_id=ctx.call_id,
            cseq=ctx.cseq,
            via_host=self.local_ip,
            via_port=self.local_port or 5060,
            transport=self.transport_name.upper(),
            from_tag=ctx.from_tag,
            contact=contact,
            extra_headers=extra,
            body=body,
        )
        ctx.cseq += 1
        self._apply_header_overrides(ctx, msg, method, step)
        return msg

    def _resolve_body(self, ctx: CallContext, method: str,
                      step: Send | None) -> tuple[bytes, str | None]:
        mc = self.config.message
        if step is not None and step.body is not None:
            ct = step.content_type or (mc.invite.content_type if method == "INVITE" else None)
            return self._substitute(ctx, step.body).encode("utf-8"), ct
        if method == "INVITE":
            if mc.invite.sdp:
                return self._substitute(ctx, mc.invite.sdp).encode("utf-8"), mc.invite.content_type
            sdp = sip.generate_sdp(self.local_ip, session_id=sip.process_id() + ctx.index)
            return sdp, mc.invite.content_type
        return b"", None

    def _apply_header_overrides(self, ctx: CallContext, msg: SIPMessage,
                                method: str, step: Send | None) -> None:
        """Apply configured and per-send header customizations.

        Precedence (low to high): config.message.extra_headers, then
        config.message.invite.extra_headers (INVITE), then the scenario's
        <header> set. Removals (config then scenario) run last. Values support
        scenario placeholders. This is also how malformed-header robustness
        cases are expressed (e.g. removing a mandatory header on purpose).
        """
        mc = self.config.message
        for name, val in mc.extra_headers.items():
            msg.headers.set(name, self._substitute(ctx, str(val)))
        if method == "INVITE":
            for name, val in mc.invite.extra_headers.items():
                msg.headers.set(name, self._substitute(ctx, str(val)))
        if step is not None:
            for name, val in step.set_headers.items():
                msg.headers.set(name, self._substitute(ctx, str(val)))
        for name in mc.remove_headers:
            msg.headers.remove(name)
        if step is not None:
            for name in step.remove_headers:
                msg.headers.remove(name)
        msg.headers.set("Content-Length", str(len(msg.body)))

    def _build_ack(self, ctx: CallContext) -> SIPMessage:
        if ctx.dialog is None or ctx.last_invite is None or ctx.last_invite_response is None:
            raise ScenarioAssertionError("ACK requested but no established INVITE dialog")
        return ctx.dialog.build_ack(
            ctx.last_invite, ctx.last_invite_response,
            self.local_ip, self.local_port or 5060, self.transport_name.upper(),
        )

    def _build_bye(self, ctx: CallContext) -> SIPMessage:
        if ctx.dialog is None:
            raise ScenarioAssertionError("BYE requested but no established dialog")
        bye = ctx.dialog.build_bye(self.local_ip, self.local_port or 5060,
                                   self.transport_name.upper())
        self.metrics.call_terminated()
        return bye

    def _build_from_template(self, ctx: CallContext, template: str) -> SIPMessage:
        text = self._substitute(ctx, template)
        msg = sip.parse(text.encode("utf-8"))
        if msg.method:
            ctx.cseq = (msg.cseq_number or ctx.cseq) + 1
        return msg

    def _substitute(self, ctx: CallContext, template: str) -> str:
        ident = self.config.identity
        branch = sip.new_branch()
        mapping = {
            "[call_id]": ctx.call_id,
            "[branch]": branch,
            "[cseq]": str(ctx.cseq),
            "[local_ip]": self.local_ip,
            "[local_port]": str(self.local_port or 5060),
            "[remote_ip]": self.config.target.host,
            "[remote_port]": str(self.config.target.port),
            "[transport]": self.transport_name.upper(),
            "[from_user]": ident.from_user,
            "[from_domain]": ident.from_domain,
            "[from_tag]": ctx.from_tag,
            "[to_user]": ident.to_user,
            "[to_domain]": ident.to_domain or self.config.target.host,
            "[contact_user]": ident.contact_user,
            "[service]": ident.to_user,
            "[len]": "0",
        }
        out = template.replace("\n", "\r\n").replace("\r\r\n", "\r\n")
        for key, val in mapping.items():
            out = out.replace(key, val)
        for name, val in ctx.variables.items():
            out = out.replace(f"[${name}]", val)
        return out

    # ----- extraction + auth ---------------------------------------------
    def _run_extractions(self, ctx: CallContext, step: Recv, msg: SIPMessage) -> None:
        for extract in step.actions:
            pattern = extract.compile()
            if extract.search_in == "hdr" and extract.header:
                haystack = "\n".join(msg.headers.get_all(extract.header))
            else:
                haystack = msg.serialize().decode("utf-8", errors="replace")
            found = pattern.findall(haystack)
            if found:
                value = found[min(extract.occurrence - 1, len(found) - 1)]
                if isinstance(value, tuple):
                    value = value[0]
                ctx.variables[extract.assign_to] = value

    def _auth_enabled(self) -> bool:
        return self.config.security.authentication.lower() == "digest"

    def _auth_retry(self, ctx: CallContext, resp: SIPMessage) -> None:
        if ctx.last_request is None:
            raise ScenarioAssertionError("auth challenge with no prior request")
        is_proxy = resp.status_code == 407
        chal_header = "Proxy-Authenticate" if is_proxy else "WWW-Authenticate"
        raw = resp.headers.get(chal_header)
        if not raw:
            raise ScenarioAssertionError(f"{resp.status_code} without {chal_header}")
        challenge = parse_challenge(raw, is_proxy=is_proxy)

        # For an INVITE challenge we must ACK the failure response first.
        if (ctx.last_request.method == "INVITE"):
            self._ack_failure(ctx, resp)

        username = self.config.security.username or self.config.identity.from_user
        password = self.config.security.password or ""
        orig = ctx.last_request
        method = orig.method or ""
        uri = orig.request_uri or ""
        auth_value = build_authorization(
            challenge, username=username, password=password, method=method, uri=uri
        )
        header_name = "Proxy-Authorization" if is_proxy else "Authorization"

        retry = sip.build_request(
            method,
            uri,
            from_uri=self._from_uri(ctx),
            to_uri=orig.headers.get("To", self._to_uri()).split(";tag=")[0],
            call_id=ctx.call_id,
            cseq=ctx.cseq,
            via_host=self.local_ip,
            via_port=self.local_port or 5060,
            transport=self.transport_name.upper(),
            from_tag=ctx.from_tag,
            contact=self._contact() if method in ("INVITE", "REGISTER") else None,
            extra_headers={header_name: auth_value,
                           **({"Content-Type": "application/sdp"} if orig.body else {})},
            body=orig.body,
        )
        ctx.cseq += 1
        ctx.auth_retried = True
        ctx.last_request = retry
        if method == "INVITE":
            ctx.last_invite = retry
        reliable = self.transport_name in ("tcp", "tls")
        ctx.current_tx = ClientTransaction(
            request=retry, branch=retry.top_via_branch() or sip.new_branch(),
            method=method, reliable=reliable,
        )
        self.on_log(f"[call {ctx.index}] >> {method} (authenticated retry)")
        self._transmit(ctx, retry)

    def _ack_failure(self, ctx: CallContext, resp: SIPMessage) -> None:
        """ACK a non-2xx INVITE response (same branch, RFC 3261 17.1.1.3)."""
        if ctx.last_invite is None:
            return
        inv = ctx.last_invite
        ack = sip.build_request(
            "ACK",
            inv.request_uri or "",
            from_uri=inv.headers.get("From", ""),
            to_uri=resp.headers.get("To", inv.headers.get("To", "")),
            call_id=ctx.call_id,
            cseq=inv.cseq_number or ctx.cseq,
            via_host=self.local_ip,
            via_port=self.local_port or 5060,
            transport=self.transport_name.upper(),
            branch=inv.top_via_branch(),
        )
        # ACK re-uses the INVITE's From (with tag) and the response's To (with tag).
        ack.headers.set("From", inv.headers.get("From", ""))
        ack.headers.set("To", resp.headers.get("To", inv.headers.get("To", "")))
        self._transmit(ctx, ack)
