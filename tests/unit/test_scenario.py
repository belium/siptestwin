import pytest

from siptestwin import scenario_parser as sp


def test_parse_builtin_options():
    s = sp.parse_string('<scenario name="o"><send request="OPTIONS"/>'
                        '<recv response="200"/></scenario>')
    assert s.name == "o"
    assert len(s.steps) == 2
    assert isinstance(s.steps[0], sp.Send)
    assert s.steps[0].builtin_method == "OPTIONS"
    assert isinstance(s.steps[1], sp.Recv)
    assert s.steps[1].response == 200


def test_template_send():
    s = sp.parse_string('<scenario><send><![CDATA[OPTIONS sip:x SIP/2.0\n\n]]></send>'
                        '<recv response="200"/></scenario>')
    assert s.steps[0].template.startswith("OPTIONS")


def test_pause_and_extraction():
    xml = ('<scenario><send request="INVITE"/>'
           '<recv response="200"><action>'
           '<ereg regexp="tag=([^;]+)" search_in="hdr" header="To" assign_to="remote_tag"/>'
           '</action></recv><pause milliseconds="100"/></scenario>')
    s = sp.parse_string(xml)
    recv = s.steps[1]
    assert recv.actions[0].assign_to == "remote_tag"
    assert isinstance(s.steps[2], sp.Pause)
    assert s.steps[2].milliseconds == 100


def test_send_header_and_body_parametrization():
    xml = ('<scenario><send request="INVITE">'
           '<header name="Subject">hi [call_id]</header>'
           '<header name="User-Agent" action="remove"/>'
           '<body content-type="application/sdp"><![CDATA[v=0\n]]></body>'
           '</send><recv response="200"/></scenario>')
    s = sp.parse_string(xml)
    send = s.steps[0]
    assert send.builtin_method == "INVITE"
    assert send.set_headers["Subject"] == "hi [call_id]"
    assert "User-Agent" in send.remove_headers
    assert send.body.startswith("v=0")
    assert send.content_type == "application/sdp"


def test_header_body_require_builtin_form():
    with pytest.raises(sp.ScenarioError):
        sp.parse_string('<scenario><send><header name="X">y</header></send></scenario>')


def test_doctype_rejected():
    with pytest.raises(sp.ScenarioError):
        sp.parse_string('<!DOCTYPE x [<!ENTITY e "y">]><scenario>'
                        '<send request="OPTIONS"/></scenario>')


def test_sendcmd_rejected():
    with pytest.raises(sp.ScenarioError):
        sp.parse_string('<scenario><sendCmd><![CDATA[x]]></sendCmd></scenario>')


def test_must_start_with_send():
    with pytest.raises(sp.ScenarioError):
        sp.parse_string('<scenario><recv response="200"/></scenario>')


def test_shipped_scenarios_parse():
    import pathlib
    root = pathlib.Path(__file__).resolve().parents[2] / "scenarios"
    for xml in root.glob("*.xml"):
        sp.parse_file(xml)
