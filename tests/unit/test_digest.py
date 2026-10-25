from siptestwin.authentication import build_authorization, parse_challenge


def test_rfc2617_known_answer():
    # RFC 2617 section 3.5 worked example.
    challenge = parse_challenge(
        'Digest realm="testrealm@host.com", '
        'nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", qop="auth", '
        'opaque="5ccc069c403ebaf9f0171e9517f40e41"'
    )
    auth = build_authorization(
        challenge,
        username="Mufasa",
        password="Circle Of Life",
        method="GET",
        uri="/dir/index.html",
        cnonce="0a4f113b",
        nc=1,
    )
    assert 'response="6629fae49393a05397450978507c4ef1"' in auth
    assert "qop=auth" in auth
    assert "nc=00000001" in auth


def test_parse_challenge_requires_realm_and_nonce():
    import pytest
    from siptestwin.authentication.digest import DigestError
    with pytest.raises(DigestError):
        parse_challenge('Digest realm="x"')


def test_no_qop_response_format():
    challenge = parse_challenge('Digest realm="r", nonce="n"')
    auth = build_authorization(challenge, username="u", password="p",
                               method="REGISTER", uri="sip:r")
    assert auth.startswith("Digest ")
    assert "qop" not in auth
    assert 'username="u"' in auth
