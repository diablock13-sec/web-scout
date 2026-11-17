import re
from pathlib import Path

import httpx
import pytest

from web_scout import client as client_module
from web_scout.client import MAX_REDIRECTS, USER_AGENT, Fetcher, FetchError
from web_scout.scope import ScopeError, build_scope

LAB = build_scope(["lab.example.com"], i_own_this=True)
URL = "http://127.0.0.1:3000/"


def serve(*responses):
    """Handler yang mencatat request. Respons terakhir diulang tanpa batas."""
    seen = []
    queue = list(responses)

    def handler(request):
        seen.append(request)
        return queue.pop(0) if len(queue) > 1 else queue[0]

    return handler, seen


def make(handler, scope=None, **kwargs):
    kwargs.setdefault("min_interval", 0)
    kwargs.setdefault("resolver", lambda host: ["127.0.0.1"])
    return Fetcher(scope, transport=httpx.MockTransport(handler), **kwargs)


def redirect(location):
    return httpx.Response(302, headers={"location": location})


# ---- koneksi ke alamat yang sudah diverifikasi ----


def test_connects_to_resolved_address_and_keeps_original_host_header():
    handler, seen = serve(httpx.Response(200))
    with make(handler) as f:
        response = f.get("http://localhost:3000/a?b=1")
    request = seen[0]
    assert request.url.host == "127.0.0.1"
    assert request.url.port == 3000
    assert request.url.path == "/a"
    assert request.url.params["b"] == "1"
    assert request.headers["host"] == "localhost:3000"
    assert response.url == "http://localhost:3000/a?b=1"
    assert response.status == 200


def test_ip_literal_never_triggers_dns():
    def no_dns(host):
        raise AssertionError("tidak boleh resolve alamat IP")

    handler, seen = serve(httpx.Response(200))
    with make(handler, resolver=no_dns) as f:
        f.get(URL)
    assert len(seen) == 1


def test_ipv6_loopback_host_header_is_bracketed():
    handler, seen = serve(httpx.Response(200))
    with make(handler) as f:
        f.get("http://[::1]:3000/")
    assert seen[0].headers["host"] == "[::1]:3000"
    assert seen[0].url.host == "::1"


def test_https_uses_sni_and_keeps_host_header():
    handler, seen = serve(httpx.Response(200))
    with make(handler, LAB, resolver=lambda host: ["10.0.0.5"]) as f:
        f.get("https://lab.example.com/x")
    request = seen[0]
    assert request.url.host == "10.0.0.5"
    assert (request.url.port or 443) == 443  # httpx menormalkan port bawaan jadi None
    assert request.headers["host"] == "lab.example.com"
    assert request.extensions["sni_hostname"] == "lab.example.com"


def test_plain_http_has_no_sni():
    handler, seen = serve(httpx.Response(200))
    with make(handler) as f:
        f.get(URL)
    assert "sni_hostname" not in seen[0].extensions


def test_user_agent_identifies_the_tool():
    handler, seen = serve(httpx.Response(200))
    with make(handler) as f:
        f.get(URL)
    assert seen[0].headers["user-agent"] == USER_AGENT
    assert "web-scout" in USER_AGENT


def test_proxy_environment_is_ignored():
    handler, _ = serve(httpx.Response(200))
    with make(handler) as f:
        assert f._client.trust_env is False


# ---- pagar lingkup ----


@pytest.mark.parametrize(
    "url",
    [
        "http://evil.example/",
        "http://169.254.169.254/",
        "http://localhost.evil.example/",
        "http://127.0.0.1@evil.example/",
    ],
)
def test_out_of_scope_target_never_sends_a_request(url):
    handler, seen = serve(httpx.Response(200))
    with make(handler) as f, pytest.raises(ScopeError):
        f.get(url)
    assert seen == []


def test_hijacked_localhost_is_rejected_before_connecting():
    handler, seen = serve(httpx.Response(200))
    with (
        make(handler, resolver=lambda host: ["203.0.113.9"]) as f,
        pytest.raises(ScopeError, match="non-loopback"),
    ):
        f.get("http://localhost:3000/")
    assert seen == []


# ---- redirect ----


def test_in_scope_redirect_is_followed_and_recorded():
    handler, seen = serve(redirect("/b"), httpx.Response(200))
    with make(handler) as f:
        response = f.get("http://127.0.0.1:3000/a")
    assert response.status == 200
    assert response.url == "http://127.0.0.1:3000/b"
    assert response.history == ("http://127.0.0.1:3000/a",)
    assert [r.url.path for r in seen] == ["/a", "/b"]


@pytest.mark.parametrize(
    "location",
    [
        "http://169.254.169.254/latest/meta-data/",
        "http://evil.example/x",
        "//evil.example/x",
        "http://127.0.0.1@evil.example/",
        "http://localhost.evil.example/",
        "file:///etc/passwd",
    ],
)
def test_redirect_out_of_scope_is_not_followed(location):
    handler, seen = serve(redirect(location))
    with make(handler) as f, pytest.raises(FetchError, match="luar lingkup"):
        f.get(URL)
    assert len(seen) == 1


def test_redirect_loop_is_stopped():
    handler, seen = serve(redirect("/loop"))
    with make(handler) as f, pytest.raises(FetchError, match="terlalu banyak redirect"):
        f.get(URL)
    assert len(seen) == MAX_REDIRECTS + 1


def test_redirect_status_without_location_is_returned_as_is():
    handler, _ = serve(httpx.Response(302))
    with make(handler) as f:
        assert f.get(URL).status == 302


# ---- galat jaringan ----


def test_network_error_becomes_fetch_error_without_details():
    def handler(request):
        raise httpx.ConnectError("rahasia-internal")

    with make(handler) as f, pytest.raises(FetchError) as info:
        f.get(URL)
    assert "ConnectError" in str(info.value)
    assert "rahasia-internal" not in str(info.value)


def test_timeout_becomes_fetch_error():
    def handler(request):
        raise httpx.ReadTimeout("lambat")

    with make(handler) as f, pytest.raises(FetchError, match="timeout"):
        f.get(URL)


# ---- isi respons ----


def test_body_is_not_read_by_default():
    handler, _ = serve(httpx.Response(200, content=b"x" * 100))
    with make(handler) as f:
        response = f.get(URL)
    assert response.body == b""
    assert response.truncated is False


def test_body_is_capped_and_marked_truncated():
    handler, _ = serve(httpx.Response(200, content=b"x" * 100))
    with make(handler) as f:
        response = f.get(URL, max_body=10)
    assert response.body == b"x" * 10
    assert response.truncated is True


def test_body_under_the_cap_is_complete():
    handler, _ = serve(httpx.Response(200, content=b"x" * 100))
    with make(handler) as f:
        response = f.get(URL, max_body=1000)
    assert len(response.body) == 100
    assert response.truncated is False


def test_repeated_headers_are_preserved():
    headers = [("set-cookie", "a=1"), ("set-cookie", "b=2")]
    handler, _ = serve(httpx.Response(200, headers=headers))
    with make(handler) as f:
        response = f.get(URL)
    assert response.headers.get_list("set-cookie") == ["a=1", "b=2"]


def test_cookies_do_not_leak_between_requests():
    handler, seen = serve(httpx.Response(200, headers={"set-cookie": "sid=abc"}))
    with make(handler) as f:
        f.get(URL)
        f.get(URL)
    assert "cookie" not in seen[1].headers


# ---- jeda antar permintaan ----


def test_requests_are_spaced_by_min_interval():
    now = [100.0]
    sleeps = []

    def sleep(seconds):
        sleeps.append(seconds)
        now[0] += seconds

    handler, _ = serve(httpx.Response(200))
    with make(handler, min_interval=1.0, sleep=sleep, clock=lambda: now[0]) as f:
        f.get(URL)
        f.get(URL)  # langsung setelahnya: harus menunggu
        now[0] += 5
        f.get(URL)  # sudah lewat 5 detik: tidak menunggu
    assert sleeps == [1.0]


def test_each_redirect_hop_is_rate_limited_too():
    now = [100.0]
    sleeps = []

    def sleep(seconds):
        sleeps.append(seconds)
        now[0] += seconds

    handler, _ = serve(redirect("/b"), httpx.Response(200))
    with make(handler, min_interval=1.0, sleep=sleep, clock=lambda: now[0]) as f:
        f.get(URL)
    assert sleeps == [1.0]


# ---- tidak ada jalan pintas ----


def test_only_the_client_module_imports_httpx():
    root = Path(client_module.__file__).parent
    pattern = re.compile(r"^\s*(?:import httpx|from httpx)", re.MULTILINE)
    offenders = [
        p.name
        for p in root.glob("*.py")
        if p.name != "client.py" and pattern.search(p.read_text(encoding="utf-8"))
    ]
    assert offenders == []
