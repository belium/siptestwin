"""End-to-end tests driving the engine against the local loopback test server."""

import pytest

from siptestwin import config as cfg
from siptestwin import scenario_parser as sp
from siptestwin.engine import Engine
from siptestwin.security_tests import malformed_catalog, validate_message
from siptestwin.testserver import run_background

pytestmark = pytest.mark.integration

SCENARIOS = "scenarios"


def _config(port, scenario, *, transport="udp", auth="disabled", **sec):
    data = {
        "target": {"host": "127.0.0.1", "port": port, "transport": transport},
        "identity": {"from_user": "tester", "from_domain": "lab.example",
                     "to_user": "1001", "contact_user": "tester"},
        "execution": {"scenario": scenario, "calls": 1, "concurrency": 1,
                      "call_rate": 5, "timeout_seconds": 3, "local_host": "127.0.0.1"},
        "security": {"authentication": auth, "authorized_targets": ["127.0.0.1"], **sec},
    }
    return cfg.from_dict(data).validate_or_raise()


def _run(config):
    scenario = sp.parse_file(config.execution.scenario)
    engine = Engine(config, scenario, simulate=False)
    return engine.run()


def test_options_200_udp():
    server = run_background(host="127.0.0.1", port=0, transport="udp")
    try:
        result = _run(_config(server.port, f"{SCENARIOS}/options.xml"))
    finally:
        server.stop()
    assert result.passed == 1
    assert result.calls[0].final_code == 200
    assert result.metrics.messages_sent >= 1


def test_options_405_when_unsupported():
    server = run_background(host="127.0.0.1", port=0, transport="udp")
    server.unsupported = {"OPTIONS"}
    try:
        # scenario expects 200 but server returns 405 -> call fails (correctly)
        result = _run(_config(server.port, f"{SCENARIOS}/options.xml"))
    finally:
        server.stop()
    assert result.failed == 1
    assert 405 in result.metrics.response_codes


def test_register_with_digest():
    server = run_background(host="127.0.0.1", port=0, transport="udp",
                            require_auth=True, username="tester", password="labpass")
    try:
        config = _config(server.port, f"{SCENARIOS}/register.xml",
                         auth="digest", username="tester", password="labpass")
        result = _run(config)
    finally:
        server.stop()
    assert result.passed == 1, [vars(c) for c in result.calls]
    assert 200 in result.metrics.response_codes


def test_register_wrong_password_rejected():
    server = run_background(host="127.0.0.1", port=0, transport="udp",
                            require_auth=True, username="tester", password="labpass")
    try:
        config = _config(server.port, f"{SCENARIOS}/register.xml",
                         auth="digest", username="tester", password="WRONG")
        result = _run(config)
    finally:
        server.stop()
    assert result.failed == 1
    assert 403 in result.metrics.response_codes


def test_basic_call_invite_ack_bye():
    server = run_background(host="127.0.0.1", port=0, transport="udp")
    try:
        result = _run(_config(server.port, f"{SCENARIOS}/basic_call.xml"))
    finally:
        server.stop()
    assert result.passed == 1, [vars(c) for c in result.calls]
    assert result.metrics.calls_established == 1
    assert result.metrics.calls_terminated == 1


def test_options_over_tcp():
    server = run_background(host="127.0.0.1", port=0, transport="tcp")
    try:
        result = _run(_config(server.port, f"{SCENARIOS}/options.xml", transport="tcp"))
    finally:
        server.stop()
    assert result.passed == 1


def test_template_scenario_runs():
    server = run_background(host="127.0.0.1", port=0, transport="udp")
    try:
        result = _run(_config(server.port, f"{SCENARIOS}/options_template.xml"))
    finally:
        server.stop()
    assert result.passed == 1


def test_invite_custom_headers_and_body():
    server = run_background(host="127.0.0.1", port=0, transport="udp")
    try:
        result = _run(_config(server.port, f"{SCENARIOS}/invite_custom.xml"))
        invites = [m for m in server.received if (m.method or "") == "INVITE"]
        assert invites, "server received no INVITE"
        inv = invites[0]
        assert inv.headers.get("Subject") == "SIPTestWin custom INVITE"
        assert inv.headers.get("Priority") == "urgent"
        assert inv.headers.get("X-Test-Id") == inv.call_id          # placeholder expanded
        assert inv.headers.get("User-Agent") == "SIPTestWin-Lab/0.1"
        assert "Allow" not in inv.headers                            # removed
        assert b"s=Custom Session" in inv.body                       # custom SDP
        assert inv.headers.get("Content-Type") == "application/sdp"
        assert int(inv.headers.get("Content-Length")) == len(inv.body)
    finally:
        server.stop()
    assert result.passed == 1, [vars(c) for c in result.calls]


def test_message_config_global_headers():
    server = run_background(host="127.0.0.1", port=0, transport="udp")
    try:
        config = _config(server.port, f"{SCENARIOS}/options.xml")
        config.message.extra_headers = {"X-Lab": "run-42", "Subject": "cfg [call_id]"}
        config.message.remove_headers = ["User-Agent"]
        result = _run(config)
        opts = [m for m in server.received if (m.method or "") == "OPTIONS"]
        assert opts
        assert opts[0].headers.get("X-Lab") == "run-42"
        assert opts[0].headers.get("Subject", "").startswith("cfg ")
        assert "User-Agent" not in opts[0].headers
    finally:
        server.stop()
    assert result.passed == 1


def test_trace_capture_during_run(tmp_path):
    from siptestwin.capture import SipTracer
    server = run_background(host="127.0.0.1", port=0, transport="udp")
    pcap = tmp_path / "run.pcap"
    text = tmp_path / "run.trace.log"
    tracer = SipTracer(text_path=text, pcap_path=pcap)
    try:
        config = _config(server.port, f"{SCENARIOS}/basic_call.xml")
        scenario = sp.parse_file(config.execution.scenario)
        from siptestwin.engine import Engine
        Engine(config, scenario, simulate=False, tracer=tracer).run()
    finally:
        tracer.close()
        server.stop()
    log = text.read_text(encoding="utf-8")
    assert "INVITE" in log and "200 OK" in log and "BYE" in log
    assert pcap.read_bytes()[:4] == b"\xa1\xb2\xc3\xd4"
    assert pcap.stat().st_size > 24


def test_malformed_messages_rejected_with_4xx():
    server = run_background(host="127.0.0.1", port=0, transport="udp")
    from siptestwin.transport.udp import UDPTransport
    import queue
    inbox: "queue.Queue" = queue.Queue()
    client = UDPTransport(bind_host="127.0.0.1", bind_port=0)
    client.start(lambda data, addr: inbox.put(data))
    try:
        cases = malformed_catalog("127.0.0.1", "127.0.0.1", server.port)
        # Every shipped malformed case should be flagged by our own validator.
        from siptestwin import sip_message as sip
        for case in cases:
            findings = validate_message(case.message)
            assert any(f.severity == "error" for f in findings) or \
                case.name == "content-length-overstated", case.name
        # And the server should reject those it can parse with a 4xx.
        for case in cases:
            if case.name in ("missing-call-id", "content-length-overstated"):
                continue  # may be dropped pre-parse; not sent here
            client.send(case.message.serialize(), ("127.0.0.1", server.port))
            try:
                resp = sip.parse(inbox.get(timeout=2))
                assert 400 <= (resp.status_code or 0) < 500, (case.name, resp.status_code)
            except queue.Empty:
                pytest.fail(f"no response to malformed case {case.name}")
    finally:
        client.close()
        server.stop()
