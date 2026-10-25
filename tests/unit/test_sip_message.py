from siptestwin import sip_message as sip


def test_build_request_has_mandatory_headers():
    msg = sip.build_request(
        "OPTIONS", "sip:example.com",
        from_uri="<sip:a@lab>", to_uri="<sip:b@example.com>",
        call_id="c1@lab", cseq=1, via_host="127.0.0.1", via_port=5060,
        from_tag="t1",
    )
    for h in ("Via", "Max-Forwards", "From", "To", "Call-ID", "CSeq"):
        assert h in msg.headers
    assert msg.cseq_number == 1
    assert msg.cseq_method == "OPTIONS"
    assert msg.top_via_branch().startswith(sip.MAGIC_COOKIE)


def test_round_trip_serialize_parse():
    msg = sip.build_request(
        "INVITE", "sip:b@example.com",
        from_uri="<sip:a@lab>", to_uri="<sip:b@example.com>",
        call_id="c2@lab", cseq=2, via_host="127.0.0.1", via_port=5060,
        from_tag="t2", body=sip.generate_sdp("127.0.0.1"),
        extra_headers={"Content-Type": "application/sdp"},
    )
    raw = msg.serialize()
    parsed = sip.parse(raw)
    assert parsed.method == "INVITE"
    assert parsed.call_id == "c2@lab"
    assert parsed.cseq_method == "INVITE"
    assert parsed.body == msg.body
    assert int(parsed.headers.get("Content-Length")) == len(msg.body)


def test_parse_response_and_classification():
    raw = (b"SIP/2.0 180 Ringing\r\nVia: SIP/2.0/UDP x;branch=z9hG4bKabc\r\n"
           b"From: <sip:a@b>;tag=1\r\nTo: <sip:c@d>;tag=2\r\n"
           b"Call-ID: c\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n")
    msg = sip.parse(raw)
    assert msg.is_response and msg.is_provisional
    assert msg.status_code == 180
    assert msg.to_tag() == "2"
    assert msg.from_tag() == "1"


def test_multiple_via_preserved():
    msg = sip.SIPMessage(status_code=200, reason_phrase="OK")
    msg.headers.add("Via", "SIP/2.0/UDP p1;branch=z9hG4bK1")
    msg.headers.add("Via", "SIP/2.0/UDP p2;branch=z9hG4bK2")
    assert len(msg.headers.get_all("Via")) == 2
    assert msg.serialize().count(b"Via:") == 2


def test_compact_header_forms():
    raw = b"SIP/2.0 200 OK\r\nv: SIP/2.0/UDP x;branch=z9hG4bK1\r\ni: call1\r\nl: 0\r\n\r\n"
    msg = sip.parse(raw)
    assert msg.call_id == "call1"
    assert msg.headers.get("Via") is not None


def test_oversized_message_rejected():
    import pytest
    big = b"OPTIONS sip:x SIP/2.0\r\n" + b"X: " + b"a" * (sip.MAX_MESSAGE_BYTES) + b"\r\n\r\n"
    with pytest.raises(sip.SIPParseError):
        sip.parse(big)
