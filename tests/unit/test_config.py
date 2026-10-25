import pytest

from siptestwin import config as cfg


def _base(**over):
    data = {
        "target": {"host": "127.0.0.1", "port": 5060, "transport": "udp"},
        "execution": {"scenario": "scenarios/options.xml", "calls": 5,
                      "concurrency": 1, "call_rate": 2},
    }
    data.update(over)
    return data


def test_valid_config():
    c = cfg.from_dict(_base())
    assert c.validate() == []


def test_missing_target_raises():
    with pytest.raises(cfg.ConfigError):
        cfg.from_dict({"execution": {"scenario": "x"}})


def test_bad_transport_reported():
    c = cfg.from_dict(_base(target={"host": "h", "transport": "sctp"}))
    errs = c.validate()
    assert any("transport" in e for e in errs)


def test_concurrency_cannot_exceed_calls():
    c = cfg.from_dict(_base(execution={"scenario": "s", "calls": 2,
                                        "concurrency": 10, "call_rate": 1}))
    assert any("concurrency" in e for e in c.validate())


def test_unknown_key_rejected():
    with pytest.raises(cfg.ConfigError):
        cfg.from_dict(_base(target={"host": "h", "bogus": 1}))


def test_load_yaml(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text(
        "target:\n  host: 127.0.0.1\n  port: 5060\nexecution:\n"
        "  scenario: scenarios/options.xml\n  calls: 1\n  concurrency: 1\n  call_rate: 1\n",
        encoding="utf-8",
    )
    c = cfg.load_and_validate(p)
    assert c.target.host == "127.0.0.1"


def test_load_json(tmp_path):
    p = tmp_path / "c.json"
    p.write_text(
        '{"target": {"host": "127.0.0.1"}, "execution": '
        '{"scenario": "s", "calls": 1, "concurrency": 1, "call_rate": 1}}',
        encoding="utf-8",
    )
    c = cfg.load_and_validate(p)
    assert c.target.port == 5060
