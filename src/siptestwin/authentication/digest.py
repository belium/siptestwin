"""SIP Digest authentication (RFC 2617, RFC 3261 section 22).

This computes the response to a server's Digest challenge using credentials
supplied for an authorized lab account. It intentionally supports only
answering a single, legitimate challenge with known credentials. It contains
no credential-guessing or brute-force functionality.

Supported algorithms: MD5, MD5-sess. Supported qop: absent and "auth".
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass


class DigestError(ValueError):
    """Raised for unsupported or malformed Digest parameters."""


def _parse_params(value: str) -> dict[str, str]:
    """Parse a comma-separated list of ``key=value`` auth parameters."""
    params: dict[str, str] = {}
    i = 0
    n = len(value)
    while i < n:
        # skip whitespace / commas
        while i < n and value[i] in ", \t":
            i += 1
        start = i
        while i < n and value[i] != "=":
            i += 1
        key = value[start:i].strip().lower()
        if i >= n:
            break
        i += 1  # skip '='
        if i < n and value[i] == '"':
            i += 1
            vstart = i
            while i < n and value[i] != '"':
                i += 1
            val = value[vstart:i]
            i += 1  # skip closing quote
        else:
            vstart = i
            while i < n and value[i] != ",":
                i += 1
            val = value[vstart:i].strip()
        if key:
            params[key] = val
    return params


@dataclass
class DigestChallenge:
    """A parsed WWW-Authenticate / Proxy-Authenticate Digest challenge."""

    scheme: str
    realm: str
    nonce: str
    algorithm: str = "MD5"
    qop: str | None = None
    opaque: str | None = None
    stale: bool = False
    is_proxy: bool = False


def parse_challenge(header_value: str, *, is_proxy: bool = False) -> DigestChallenge:
    """Parse a ``WWW-Authenticate``/``Proxy-Authenticate`` header value."""
    value = header_value.strip()
    scheme, _, rest = value.partition(" ")
    if scheme.lower() != "digest":
        raise DigestError(f"unsupported auth scheme: {scheme!r}")
    params = _parse_params(rest)
    if "realm" not in params or "nonce" not in params:
        raise DigestError("Digest challenge missing realm or nonce")
    return DigestChallenge(
        scheme="Digest",
        realm=params["realm"],
        nonce=params["nonce"],
        algorithm=params.get("algorithm", "MD5"),
        qop=params.get("qop"),
        opaque=params.get("opaque"),
        stale=params.get("stale", "false").lower() == "true",
        is_proxy=is_proxy,
    )


def _h(data: str, algorithm: str) -> str:
    algo = algorithm.lower().replace("-sess", "")
    if algo == "md5":
        return hashlib.md5(data.encode("utf-8")).hexdigest()
    if algo == "sha-256":
        return hashlib.sha256(data.encode("utf-8")).hexdigest()
    raise DigestError(f"unsupported Digest algorithm: {algorithm!r}")


def build_authorization(
    challenge: DigestChallenge,
    *,
    username: str,
    password: str,
    method: str,
    uri: str,
    cnonce: str | None = None,
    nc: int = 1,
) -> str:
    """Compute the Authorization / Proxy-Authorization header value.

    Returns the full header value string (starting with ``Digest ``). The
    caller adds it under the correct header name.
    """
    algorithm = challenge.algorithm
    qop = None
    if challenge.qop:
        offered = [q.strip().lower() for q in challenge.qop.split(",")]
        if "auth" in offered:
            qop = "auth"
        else:
            raise DigestError(f"unsupported qop offered: {challenge.qop!r}")

    ha1 = _h(f"{username}:{challenge.realm}:{password}", algorithm)
    if algorithm.lower().endswith("-sess"):
        cnonce = cnonce or secrets.token_hex(8)
        ha1 = _h(f"{ha1}:{challenge.nonce}:{cnonce}", algorithm)

    ha2 = _h(f"{method}:{uri}", algorithm)

    if qop == "auth":
        cnonce = cnonce or secrets.token_hex(8)
        nc_value = f"{nc:08x}"
        response = _h(
            f"{ha1}:{challenge.nonce}:{nc_value}:{cnonce}:{qop}:{ha2}", algorithm
        )
    else:
        response = _h(f"{ha1}:{challenge.nonce}:{ha2}", algorithm)

    parts = [
        f'username="{username}"',
        f'realm="{challenge.realm}"',
        f'nonce="{challenge.nonce}"',
        f'uri="{uri}"',
        f'response="{response}"',
        f"algorithm={algorithm}",
    ]
    if qop == "auth":
        parts.append("qop=auth")
        parts.append(f"nc={nc:08x}")
        parts.append(f'cnonce="{cnonce}"')
    if challenge.opaque is not None:
        parts.append(f'opaque="{challenge.opaque}"')
    return "Digest " + ", ".join(parts)
