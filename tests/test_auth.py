"""
Unit tests for auth classes.

Integration tests also exist in tests/client/test_auth.py
"""
import typing
from urllib.request import parse_http_list, parse_keqv_list

import pytest

import httpx


def _digest_fields(authorization: str) -> typing.Dict[str, str]:
    assert authorization.startswith("Digest ")
    return parse_keqv_list(parse_http_list(authorization[len("Digest ") :]))


def _send_401(
    flow: typing.Generator[httpx.Request, httpx.Response, None],
    request: httpx.Request,
    www_authenticate: str,
) -> httpx.Request:
    response = httpx.Response(
        content=b"Auth required",
        status_code=401,
        headers={"WWW-Authenticate": www_authenticate},
        request=request,
    )
    return flow.send(response)


def _finish(flow: typing.Generator[httpx.Request, httpx.Response, None]) -> None:
    with pytest.raises(StopIteration):
        flow.send(httpx.Response(content=b"Hello, world!", status_code=200))


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


def test_digest_auth_rfc2069_no_qop_uses_legacy_request_digest() -> None:
    # Fixed worked example from RFC 2617 section 3.2.2, with the "qop"
    # parameter omitted as in the original RFC 2069 challenge format.
    auth = httpx.DigestAuth(username="Mufasa", password="Circle Of Life")
    request = httpx.Request("GET", "http://www.example.org/dir/index.html")

    flow = auth.sync_auth_flow(request)
    request = next(flow)
    assert "Authorization" not in request.headers

    # A legacy challenge only carries realm and nonce (opaque optional);
    # there is no qop, algorithm or cnonce.
    request = _send_401(
        flow,
        request,
        'Digest realm="testrealm@host.com", '
        'nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", '
        'opaque="5ccc069c403ebaf9f0171e9517f40e41"',
    )
    authorization = request.headers["Authorization"]
    fields = _digest_fields(authorization)

    # RFC 2069 request-digest: KD(H(A1), unq(nonce):H(A2))
    assert fields["response"] == "670fd8c2df070c60b045671b8b24ff02"
    assert fields["username"] == "Mufasa"
    assert fields["realm"] == "testrealm@host.com"
    assert fields["nonce"] == "dcd98b7102dd2f0e8b11d0f600bfb0c093"
    assert fields["uri"] == "/dir/index.html"
    assert fields["opaque"] == "5ccc069c403ebaf9f0171e9517f40e41"
    # MD5 is the default algorithm when the challenge omits "algorithm".
    assert fields["algorithm"] == "MD5"

    # qop-mode parameters must not be present in legacy mode.
    assert "qop" not in fields
    assert "nc" not in fields
    assert "cnonce" not in fields
    assert ", qop=" not in authorization
    assert ", nc=" not in authorization
    assert ", cnonce=" not in authorization

    # Legacy responses use no client nonce, so the result is fully
    # deterministic: a fresh auth object facing the same challenge
    # produces exactly the same Authorization header.
    challenge = auth._last_challenge
    assert challenge is not None
    other = httpx.DigestAuth(username="Mufasa", password="Circle Of Life")
    repeat = httpx.Request("GET", "http://www.example.org/dir/index.html")
    assert other._build_auth_header(repeat, challenge) == authorization
    _finish(flow)


@pytest.mark.parametrize(
    "algorithm,expected_response",
    [
        # RFC 7616 section 3.9.1 (qop=auth, MD5 response)
        ("MD5", "8ca523f5e9506fed4657c9700eebdbec"),
        # RFC 7616 section 3.9.1 (qop=auth, SHA-256 response)
        (
            "SHA-256",
            "753927fa0e85d155564e2e272a28d1802ca10daf449" "6794697cf8db5856cb6c1",
        ),
    ],
)
def test_digest_auth_rfc7616_qop_auth_fixed_vectors(
    monkeypatch: pytest.MonkeyPatch,
    algorithm: str,
    expected_response: str,
) -> None:
    auth = httpx.DigestAuth(username="Mufasa", password="Circle of Life")
    # Pin the client nonce to the value used in the RFC 7616 worked example.
    monkeypatch.setattr(
        auth,
        "_get_client_nonce",
        lambda count, nonce: b"f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ",
    )

    request = httpx.Request("GET", "http://www.example.org/dir/index.html")
    flow = auth.sync_auth_flow(request)
    request = next(flow)

    request = _send_401(
        flow,
        request,
        'Digest realm="http-auth@example.org", '
        'qop="auth, auth-int", '
        f"algorithm={algorithm}, "
        'nonce="7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v", '
        'opaque="FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS"',
    )
    fields = _digest_fields(request.headers["Authorization"])

    assert fields["response"] == expected_response
    assert fields["algorithm"] == algorithm
    assert fields["qop"] == "auth"
    assert fields["nc"] == "00000001"
    assert fields["cnonce"] == "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ"
    assert fields["opaque"] == "FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS"

    _finish(flow)


def test_digest_auth_legacy_then_modern_challenge_does_not_leak_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    auth = httpx.DigestAuth(username="Mufasa", password="Circle Of Life")
    url = "http://www.example.org/dir/index.html"

    # First transaction: an old RFC 2069 device (no qop).
    request = httpx.Request("GET", url)
    flow = auth.sync_auth_flow(request)
    request = next(flow)
    request = _send_401(
        flow,
        request,
        'Digest realm="testrealm@host.com", '
        'nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", '
        'opaque="5ccc069c403ebaf9f0171e9517f40e41"',
    )
    legacy_authorization = request.headers["Authorization"]
    legacy_fields = _digest_fields(legacy_authorization)
    assert legacy_fields["response"] == "670fd8c2df070c60b045671b8b24ff02"
    assert {"qop", "nc", "cnonce"}.isdisjoint(legacy_fields)
    _finish(flow)

    # A new request proactively reuses the cached legacy challenge...
    monkeypatch.setattr(auth, "_get_client_nonce", lambda count, nonce: b"0a4f113b")
    request = httpx.Request("GET", url)
    flow = auth.sync_auth_flow(request)
    request = next(flow)
    fields = _digest_fields(request.headers["Authorization"])
    assert fields["response"] == "670fd8c2df070c60b045671b8b24ff02"
    assert {"qop", "nc", "cnonce"}.isdisjoint(fields)

    # ...then the server answers with a modern qop=auth challenge. The
    # response must use the qop digest formula, and the nonce count must
    # restart at 1 rather than carry over legacy bookkeeping.
    request = _send_401(
        flow,
        request,
        'Digest realm="testrealm@host.com", qop="auth", '
        'nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", '
        'opaque="5ccc069c403ebaf9f0171e9517f40e41"',
    )
    fields = _digest_fields(request.headers["Authorization"])
    assert fields["response"] == "6629fae49393a05397450978507c4ef1"
    assert fields["qop"] == "auth"
    assert fields["nc"] == "00000001"
    assert fields["cnonce"] == "0a4f113b"
    _finish(flow)

    # A follow-up request reuses the modern challenge; the counter
    # continues from 2 and the qop digest formula is still used.
    request = httpx.Request("GET", url)
    flow = auth.sync_auth_flow(request)
    request = next(flow)
    fields = _digest_fields(request.headers["Authorization"])
    assert fields["nc"] == "00000002"
    assert fields["response"] == "15b6bb427e3fecd23a43cb702ce447d5"
    assert fields["qop"] == "auth"
    _finish(flow)
