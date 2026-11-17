import socket

import pytest

from web_scout import scope
from web_scout.scope import (
    ScopeError,
    build_scope,
    check_connectable,
    check_target,
    parse_target,
    resolve_host,
    verify_resolved,
)

LAB = build_scope(["lab.example.com", "192.168.1.10"], i_own_this=True)


# ---- loopback diizinkan tanpa flag ----


@pytest.mark.parametrize(
    ("url", "port"),
    [
        ("http://127.0.0.1:3000", 3000),
        ("http://localhost:3000/", 3000),
        ("http://[::1]:3000/", 3000),
        ("http://[::ffff:127.0.0.1]:3000/", 3000),
        ("http://127.5.5.5/", 80),
        ("https://localhost", 443),
        ("http://localhost./", 80),
        ("HTTP://LocalHost:3000/", 3000),
    ],
)
def test_loopback_allowed_by_default(url, port):
    target = check_target(url)
    assert target.loopback is True
    assert target.port == port


def test_url_is_normalised_and_fragment_dropped():
    assert parse_target("HTTP://LocalHost:3000/Path?q=1#frag").url == (
        "http://localhost:3000/Path?q=1"
    )
    assert parse_target("http://[::1]:3000").url == "http://[::1]:3000/"


# ---- di luar lingkup ----


@pytest.mark.parametrize(
    "url",
    [
        "http://evil.example/",
        "http://localhost.evil.example/",
        "http://127.0.0.1.evil.example/",
        "http://localhost-evil.example/",
        "http://notlocalhost/",
        "http://localhost.localdomain/",
        "http://evil.example#@127.0.0.1/",
        "http://evil.example?@127.0.0.1/",
        "http://10.0.0.5/",
        "http://192.168.1.10:3000/",
        "http://0.0.0.0:3000/",
        "http://[::]/",
        "http://169.254.169.254/latest/meta-data/",
        "http://2130706433/",
        "http://0x7f.0.0.1/",
        "http://0177.0.0.1/",
        "http://127.1/",
        "http://127.000.000.001/",
    ],
)
def test_out_of_scope_is_rejected(url):
    with pytest.raises(ScopeError, match="di luar lingkup"):
        check_target(url)


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1@evil.example/",
        "http://evil.example@127.0.0.1/",
        "http://user:pw@127.0.0.1:3000/",
        "http://lab.example.com@127.0.0.1/",
    ],
)
def test_credentials_in_url_are_rejected_even_when_host_is_allowed(url):
    with pytest.raises(ScopeError, match="kredensial"):
        check_target(url, LAB)


@pytest.mark.parametrize(
    "url",
    [
        None,
        "",
        "127.0.0.1:3000",
        "//127.0.0.1/",
        "file:///etc/passwd",
        "ftp://127.0.0.1/",
        "javascript:alert(1)",
        "http:///path",
        "http://:3000/",
        "http://127.0.0.1:99999/",
        "http://127.0.0.1:0/",
        "http://127.0.0.1:abc/",
        "http://127.0.0.1:3000.evil.example/",
        "http://[::1/",
        "http://localhost%2eevil.example/",
        "http://.localhost/",
        "http://localhost../",
        "http://127.0.0.1:3000\\@evil.example/",
        "http://127.0.0.1:3000/ ",
        "http://127.0.0.1/\n",
        "http://127.0.0.1/\t",
        "http://127.0.0.1\x00.evil.example/",
        "http://127.0.0.1/é",
        "http://localhost/\u202e",
        "http://ｌocalhost/",
    ],
)
def test_malformed_urls_are_rejected(url):
    with pytest.raises(ScopeError):
        check_target(url)


def test_default_scope_does_not_include_allowed_hosts_of_other_scopes():
    with pytest.raises(ScopeError, match="di luar lingkup"):
        check_target("https://lab.example.com/")


# ---- --allow dan --i-own-this ----


def test_allow_requires_ownership_flag():
    with pytest.raises(ScopeError, match="--i-own-this"):
        build_scope(["lab.example.com"])


def test_ownership_flag_without_allow_is_an_error():
    with pytest.raises(ScopeError, match="tanpa --allow"):
        build_scope(i_own_this=True)


@pytest.mark.parametrize(
    "entry",
    [
        "*",
        "*.example.com",
        "example.*",
        "http://lab.example.com",
        "lab.example.com:8080",
        "lab.example.com/path",
        "10.0.0.0/8",
        "user@lab.example.com",
        "[::1]",
        "intranet",
        "com",
        "0.0.0.0",
        "::",
        "",
        "lab example.com",
        "lab..example.com",
        "-bad.example.com",
    ],
)
def test_bad_allow_entries_are_rejected(entry):
    with pytest.raises(ScopeError):
        build_scope([entry], i_own_this=True)


def test_allow_entries_are_normalised():
    scope_ = build_scope(["Lab.Example.COM", "2001:0DB8::1"], i_own_this=True)
    assert scope_.allowed == frozenset({"lab.example.com", "2001:db8::1"})


@pytest.mark.parametrize(
    "url",
    [
        "https://lab.example.com:8443/x",
        "https://LAB.example.com/",
        "http://192.168.1.10:3000/",
        "http://127.0.0.1:3000/",
    ],
)
def test_allowed_hosts_pass(url):
    assert check_target(url, LAB)


@pytest.mark.parametrize(
    "url",
    [
        "https://other.example.com/",
        "https://lab.example.com.evil.example/",
        "https://evil-lab.example.com/",
        "https://sub.lab.example.com/",
        "http://192.168.1.100/",
        "http://192.168.1.1/",
    ],
)
def test_lookalike_hosts_of_allowed_ones_are_rejected(url):
    with pytest.raises(ScopeError, match="di luar lingkup"):
        check_target(url, LAB)


def test_allowed_ipv6_literal_matches_any_spelling():
    scope_ = build_scope(["2001:db8::1"], i_own_this=True)
    assert check_target("http://[2001:0DB8::1]/", scope_)


def test_redirect_target_is_checked_like_any_other_url():
    # Pemanggil wajib memeriksa Location tiap redirect: ke metadata cloud harus ditolak.
    check_target("http://127.0.0.1:3000/redirect")
    with pytest.raises(ScopeError):
        check_target("http://169.254.169.254/latest/meta-data/")


# ---- setelah DNS ----


def test_loopback_target_may_only_resolve_to_loopback():
    target = parse_target("http://localhost:3000/")
    verify_resolved(target, ["127.0.0.1"])
    verify_resolved(target, ["::1", "127.0.0.1"])
    for bad in (["93.184.216.34"], ["127.0.0.1", "10.0.0.5"], ["tidak-valid"]):
        with pytest.raises(ScopeError, match="non-loopback"):
            verify_resolved(target, bad)


def test_unresolvable_host_is_rejected():
    with pytest.raises(ScopeError, match="tidak bisa di-resolve"):
        verify_resolved(parse_target("http://localhost/"), [])


def test_allowed_host_may_resolve_anywhere():
    target = check_target("https://lab.example.com/", LAB)
    verify_resolved(target, ["10.0.0.5"])


def test_check_connectable_skips_dns_for_ip_literals():
    def never_called(host):
        raise AssertionError("tidak boleh resolve alamat IP")

    target = parse_target("http://127.0.0.1:3000/")
    assert check_connectable(target, never_called) == ["127.0.0.1"]


def test_check_connectable_catches_hijacked_localhost():
    target = parse_target("http://localhost:3000/")
    assert check_connectable(target, lambda host: ["::1"]) == ["::1"]
    with pytest.raises(ScopeError, match="non-loopback"):
        check_connectable(target, lambda host: ["203.0.113.9"])


def test_resolve_host_returns_sorted_unique_addresses(monkeypatch):
    infos = [
        (socket.AF_INET, 0, 0, "", ("127.0.0.1", 0)),
        (socket.AF_INET6, 0, 0, "", ("::1", 0, 0, 0)),
        (socket.AF_INET, 0, 0, "", ("127.0.0.1", 0)),
    ]
    monkeypatch.setattr(scope.socket, "getaddrinfo", lambda *a, **k: infos)
    assert resolve_host("localhost") == ["127.0.0.1", "::1"]


def test_resolve_host_failure_becomes_scope_error(monkeypatch):
    def fail(*args, **kwargs):
        raise socket.gaierror("tidak ada")

    monkeypatch.setattr(scope.socket, "getaddrinfo", fail)
    with pytest.raises(ScopeError, match="tidak bisa di-resolve"):
        resolve_host("tidak-ada.example")
