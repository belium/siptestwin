from siptestwin import sip_message as sip
from siptestwin.metrics import Metrics
from siptestwin.transaction import ClientTransaction, TxState


def test_percentiles():
    m = Metrics()
    for v in [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]:
        m.latency(v)
    p = m.latency_percentiles()
    assert p["count"] == 10
    assert p["min_ms"] == 10
    assert p["max_ms"] == 100
    assert 50 <= p["p50_ms"] <= 60
    assert p["p95_ms"] >= p["p50_ms"]


def test_response_categories():
    m = Metrics()
    m.received(200)
    m.received(200)
    m.received(404)
    cats = m.response_by_category()
    assert cats["2xx"] == 2
    assert cats["4xx"] == 1


def test_transaction_matching_and_state():
    req = sip.build_request("INVITE", "sip:b@x", from_uri="<sip:a@l>",
                            to_uri="<sip:b@x>", call_id="c", cseq=1,
                            via_host="127.0.0.1", via_port=5060, from_tag="t")
    branch = req.top_via_branch()
    tx = ClientTransaction(request=req, branch=branch, method="INVITE", reliable=False)
    assert tx.state is TxState.CALLING

    resp = sip.build_response(req, 180)
    assert tx.matches(resp)
    tx.on_response(resp)
    assert tx.state is TxState.PROCEEDING

    ok = sip.build_response(req, 200, to_tag="s")
    tx.on_response(ok)
    assert tx.state is TxState.TERMINATED


def test_non_invite_retransmit_schedule():
    req = sip.build_request("OPTIONS", "sip:x", from_uri="<sip:a@l>",
                            to_uri="<sip:b@x>", call_id="c", cseq=1,
                            via_host="127.0.0.1", via_port=5060, from_tag="t")
    tx = ClientTransaction(request=req, branch=req.top_via_branch(),
                           method="OPTIONS", reliable=False)
    assert tx.due_for_retransmit(tx._last_tx_at + 1.0)
    # Reliable transport never retransmits.
    tx2 = ClientTransaction(request=req, branch=req.top_via_branch(),
                            method="OPTIONS", reliable=True)
    assert not tx2.due_for_retransmit(tx2._last_tx_at + 10.0)
