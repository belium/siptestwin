import struct

from siptestwin import netutils
from siptestwin.capture import PcapWriter, SipTracer, _synthesize_udp_packet


def test_list_local_ipv4_includes_loopback():
    addrs = netutils.list_local_ipv4()
    ips = [a.ip for a in addrs]
    assert "127.0.0.1" in ips
    assert all(isinstance(a.label, str) for a in addrs)


def test_default_local_ip_is_a_string():
    ip = netutils.default_local_ip()
    assert isinstance(ip, str) and ip.count(".") == 3


def test_synthesized_packet_structure():
    payload = b"OPTIONS sip:x SIP/2.0\r\n\r\n"
    frame = _synthesize_udp_packet("127.0.0.1", 5000, "127.0.0.2", 5060, payload)
    # Ethernet(14) + IP(20) + UDP(8) + payload
    assert len(frame) == 14 + 20 + 8 + len(payload)
    assert frame[12:14] == b"\x08\x00"            # IPv4 ethertype
    assert frame[14] == 0x45                        # IPv4, IHL=5
    # UDP destination port is at offset 14+20+2
    dport = struct.unpack("!H", frame[14 + 20 + 2:14 + 20 + 4])[0]
    assert dport == 5060
    assert frame.endswith(payload)


def test_pcap_writer_and_tracer(tmp_path):
    pcap = tmp_path / "t.pcap"
    text = tmp_path / "t.log"
    tracer = SipTracer(text_path=text, pcap_path=pcap)
    tracer.bind("127.0.0.1", 5000, "127.0.0.2", "udp")
    tracer.record("sent", b"OPTIONS sip:x SIP/2.0\r\nCall-ID: a\r\n\r\n", ("127.0.0.2", 5060))
    tracer.record("recv", b"SIP/2.0 200 OK\r\nCall-ID: a\r\n\r\n", ("127.0.0.2", 5060))
    tracer.close()

    # pcap global header magic
    data = pcap.read_bytes()
    assert data[:4] == b"\xa1\xb2\xc3\xd4"
    assert len(data) > 24  # header + at least one packet
    log = text.read_text(encoding="utf-8")
    assert "SENT" in log and "RECV" in log and "200 OK" in log


def test_tracer_redacts_credentials_in_text(tmp_path):
    text = tmp_path / "t.log"
    tracer = SipTracer(text_path=text)
    tracer.bind("127.0.0.1", 5000, "127.0.0.2", "udp")
    msg = (b"REGISTER sip:x SIP/2.0\r\n"
           b'Authorization: Digest username="u", response="deadbeefdeadbeef"\r\n\r\n')
    tracer.record("sent", msg, ("127.0.0.2", 5060))
    tracer.close()
    log = text.read_text(encoding="utf-8")
    assert "deadbeefdeadbeef" not in log
    assert "<redacted>" in log
