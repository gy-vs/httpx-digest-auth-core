"""
Unit tests for auth classes.

Integration tests also exist in tests/client/test_auth.py
"""
from urllib.request import parse_keqv_list

import pytest

import httpx


def test_basic_auth():
    auth = httpx.BasicAuth(username="user", password="pass")
    request = httpx.Request("GET", "https://www.example.com")

    # The initial request should include a basic auth header.
    flow = auth.sync_auth_flow(request)
    request = next(flow)
    assert request.headers["Authorization"].startswith("Basic")

    # No other requests are made.
    response = httpx.Response(content=b"Hello, world!", status_code=200)
    with pytest.raises(StopIteration):
        flow.send(response)


def test_digest_auth_with_200():
    auth = httpx.DigestAuth(username="user", password="pass")
    request = httpx.Request("GET", "https://www.example.com")

    # The initial request should not include an auth header.
    flow = auth.sync_auth_flow(request)
    request = next(flow)
    assert "Authorization" not in request.headers

    # If a 200 response is returned, then no other requests are made.
    response = httpx.Response(content=b"Hello, world!", status_code=200)
    with pytest.raises(StopIteration):
        flow.send(response)


def test_digest_auth_with_401():
    auth = httpx.DigestAuth(username="user", password="pass")
    request = httpx.Request("GET", "https://www.example.com")

    # The initial request should not include an auth header.
    flow = auth.sync_auth_flow(request)
    request = next(flow)
    assert "Authorization" not in request.headers

    # If a 401 response is returned, then a digest auth request is made.
    headers = {
        "WWW-Authenticate": 'Digest realm="...", qop="auth", nonce="...", opaque="..."'
    }
    response = httpx.Response(
        content=b"Auth required", status_code=401, headers=headers, request=request
    )
    request = flow.send(response)
    assert request.headers["Authorization"].startswith("Digest")

    # No other requests are made.
    response = httpx.Response(content=b"Hello, world!", status_code=200)
    with pytest.raises(StopIteration):
        flow.send(response)


def test_digest_auth_with_401_nonce_counting():
    auth = httpx.DigestAuth(username="user", password="pass")
    request = httpx.Request("GET", "https://www.example.com")

    # The initial request should not include an auth header.
    flow = auth.sync_auth_flow(request)
    request = next(flow)
    assert "Authorization" not in request.headers

    # If a 401 response is returned, then a digest auth request is made.
    headers = {
        "WWW-Authenticate": 'Digest realm="...", qop="auth", nonce="...", opaque="..."'
    }
    response = httpx.Response(
        content=b"Auth required", status_code=401, headers=headers, request=request
    )
    first_request = flow.send(response)
    assert first_request.headers["Authorization"].startswith("Digest")

    # Each subsequent request contains the digest header by default...
    request = httpx.Request("GET", "https://www.example.com")
    flow = auth.sync_auth_flow(request)
    second_request = next(flow)
    assert second_request.headers["Authorization"].startswith("Digest")

    # ... and the client nonce count (nc) is increased
    first_nc = parse_keqv_list(first_request.headers["Authorization"].split(", "))["nc"]
    second_nc = parse_keqv_list(second_request.headers["Authorization"].split(", "))[
        "nc"
    ]
    assert int(first_nc, 16) + 1 == int(second_nc, 16)

    # No other requests are made.
    response = httpx.Response(content=b"Hello, world!", status_code=200)
    with pytest.raises(StopIteration):
        flow.send(response)


# The challenge and credentials from the examples in RFC 2069, section 2.4
# and RFC 2617/7616, section 3.5.
RFC_EXAMPLE_CHALLENGE = (
    'Digest realm="testrealm@host.com", '
    'nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", '
    'opaque="5ccc069c403ebaf9f0171e9517f40e41"'
)
RFC_EXAMPLE_CHALLENGE_WITH_QOP = (
    'Digest realm="testrealm@host.com", '
    'qop="auth,auth-int", '
    'nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", '
    'opaque="5ccc069c403ebaf9f0171e9517f40e41"'
)


def test_digest_auth_rfc_2069_example():
    """
    A challenge without 'qop' uses the RFC 2069 response digest,
    computed as `H(HA1:nonce:HA2)`, and the 'Authorization' header
    does not include 'qop', 'nc' or 'cnonce'.

    Uses the fixed example from RFC 2069, section 2.4. Note that the
    response value printed there is a known erratum: the value below is
    what the RFC 2069, section 2.1.2 formula produces, using the HA1/HA2
    intermediates documented in RFC 2617, section 3.5.
    """
    auth = httpx.DigestAuth(username="Mufasa", password="Circle Of Life")
    request = httpx.Request("GET", "http://www.nowhere.org/dir/index.html")

    # The initial request should not include an auth header.
    flow = auth.sync_auth_flow(request)
    request = next(flow)
    assert "Authorization" not in request.headers

    # A 401 response with a legacy challenge, without any 'qop'.
    headers = {"WWW-Authenticate": RFC_EXAMPLE_CHALLENGE}
    response = httpx.Response(
        content=b"Auth required", status_code=401, headers=headers, request=request
    )
    request = flow.send(response)

    expected = (
        'Digest username="Mufasa", '
        'realm="testrealm@host.com", '
        'nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", '
        'uri="/dir/index.html", '
        'response="670fd8c2df070c60b045671b8b24ff02", '
        "algorithm=MD5, "
        'opaque="5ccc069c403ebaf9f0171e9517f40e41"'
    )
    assert request.headers["Authorization"] == expected

    # No other requests are made.
    response = httpx.Response(content=b"Hello, world!", status_code=200)
    with pytest.raises(StopIteration):
        flow.send(response)


def test_digest_auth_rfc_7616_example(monkeypatch):
    """
    A challenge with 'qop' uses the RFC 7616 response digest, computed as
    `H(HA1:nonce:nc:cnonce:qop:HA2)`.

    Uses the fixed example from RFC 2617/7616, section 3.5, with a
    patched client nonce to keep the digest deterministic.
    """
    monkeypatch.setattr(
        httpx.DigestAuth,
        "_get_client_nonce",
        lambda self, nonce_count, nonce: b"0a4f113b",
    )
    auth = httpx.DigestAuth(username="Mufasa", password="Circle Of Life")
    request = httpx.Request("GET", "http://www.nowhere.org/dir/index.html")

    flow = auth.sync_auth_flow(request)
    request = next(flow)
    assert "Authorization" not in request.headers

    headers = {"WWW-Authenticate": RFC_EXAMPLE_CHALLENGE_WITH_QOP}
    response = httpx.Response(
        content=b"Auth required", status_code=401, headers=headers, request=request
    )
    request = flow.send(response)

    expected = (
        'Digest username="Mufasa", '
        'realm="testrealm@host.com", '
        'nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", '
        'uri="/dir/index.html", '
        'response="6629fae49393a05397450978507c4ef1", '
        "algorithm=MD5, "
        'opaque="5ccc069c403ebaf9f0171e9517f40e41", '
        "qop=auth, "
        "nc=00000001, "
        'cnonce="0a4f113b"'
    )
    assert request.headers["Authorization"] == expected

    # No other requests are made.
    response = httpx.Response(content=b"Hello, world!", status_code=200)
    with pytest.raises(StopIteration):
        flow.send(response)


def test_digest_auth_legacy_challenge_then_modern_challenge(monkeypatch):
    """
    A single `DigestAuth` instance handling an RFC 2069 challenge (no 'qop')
    followed by an RFC 7616 challenge (with 'qop') must not leak state
    between the two: the nonce count is reset and the response digest
    matches the modern challenge only.
    """
    monkeypatch.setattr(
        httpx.DigestAuth,
        "_get_client_nonce",
        lambda self, nonce_count, nonce: b"0a4f113b",
    )
    auth = httpx.DigestAuth(username="Mufasa", password="Circle Of Life")

    # Handle a legacy RFC 2069 challenge first.
    request = httpx.Request("GET", "http://www.nowhere.org/dir/index.html")
    flow = auth.sync_auth_flow(request)
    request = next(flow)
    headers = {"WWW-Authenticate": RFC_EXAMPLE_CHALLENGE}
    response = httpx.Response(
        content=b"Auth required", status_code=401, headers=headers, request=request
    )
    request = flow.send(response)
    assert "qop" not in request.headers["Authorization"]
    with pytest.raises(StopIteration):
        flow.send(httpx.Response(content=b"Hello, world!", status_code=200))

    # A subsequent request starts out with the cached legacy challenge...
    request = httpx.Request("GET", "http://www.nowhere.org/dir/index.html")
    flow = auth.sync_auth_flow(request)
    request = next(flow)
    assert "qop" not in request.headers["Authorization"]

    # ...and then handles a modern RFC 7616 challenge.
    headers = {"WWW-Authenticate": RFC_EXAMPLE_CHALLENGE_WITH_QOP}
    response = httpx.Response(
        content=b"Auth required", status_code=401, headers=headers, request=request
    )
    request = flow.send(response)

    # The nonce count is reset for the new challenge, and the digest
    # matches the RFC 2617/7616 example.
    expected = (
        'Digest username="Mufasa", '
        'realm="testrealm@host.com", '
        'nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", '
        'uri="/dir/index.html", '
        'response="6629fae49393a05397450978507c4ef1", '
        "algorithm=MD5, "
        'opaque="5ccc069c403ebaf9f0171e9517f40e41", '
        "qop=auth, "
        "nc=00000001, "
        'cnonce="0a4f113b"'
    )
    assert request.headers["Authorization"] == expected

    # No other requests are made.
    response = httpx.Response(content=b"Hello, world!", status_code=200)
    with pytest.raises(StopIteration):
        flow.send(response)


def set_cookies(request: httpx.Request) -> httpx.Response:
    headers = {
        "Set-Cookie": "session=.session_value...",
        "WWW-Authenticate": 'Digest realm="...", qop="auth", nonce="...", opaque="..."',
    }
    if request.url.path == "/auth":
        return httpx.Response(
            content=b"Auth required", status_code=401, headers=headers
        )
    else:
        raise NotImplementedError()  # pragma: no cover


def test_digest_auth_setting_cookie_in_request():
    url = "https://www.example.com/auth"
    client = httpx.Client(transport=httpx.MockTransport(set_cookies))
    request = client.build_request("GET", url)

    auth = httpx.DigestAuth(username="user", password="pass")
    flow = auth.sync_auth_flow(request)
    request = next(flow)
    assert "Authorization" not in request.headers

    response = client.get(url)
    assert len(response.cookies) > 0
    assert response.cookies["session"] == ".session_value..."

    request = flow.send(response)
    assert request.headers["Authorization"].startswith("Digest")
    assert request.headers["Cookie"] == "session=.session_value..."

    # No other requests are made.
    response = httpx.Response(
        content=b"Hello, world!", status_code=200, request=request
    )
    with pytest.raises(StopIteration):
        flow.send(response)
