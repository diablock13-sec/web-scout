import json

import httpx
import pytest

from web_scout.cli import main
from web_scout.client import Fetcher

GOOD = [
    ("content-type", "text/html"),
    ("content-security-policy", "default-src 'self'; frame-ancestors 'none'"),
    ("strict-transport-security", "max-age=31536000"),
    ("x-content-type-options", "nosniff"),
]
BARE = [("content-type", "text/html")]


def factory(handler, resolver=None):
    """Pabrik Fetcher dengan transport palsu: tidak ada jaringan sungguhan."""

    def make(scope):
        return Fetcher(
            scope,
            transport=httpx.MockTransport(handler),
            min_interval=0,
            resolver=resolver or (lambda host: ["127.0.0.1"]),
        )

    return make


def reply(headers, status=200, seen=None):
    def handler(request):
        if seen is not None:
            seen.append(request)
        return httpx.Response(status, headers=headers)

    return handler


# ---- hasil dan kode keluar ----


def test_clean_site_exits_zero(capsys):
    code = main(["headers", "https://127.0.0.1:3000/"], make_fetcher=factory(reply(GOOD)))
    assert code == 0
    assert "Tidak ada temuan" in capsys.readouterr().out


def test_findings_exit_one_and_are_listed_with_advice(capsys):
    code = main(["headers", "http://127.0.0.1:3000/"], make_fetcher=factory(reply(BARE)))
    assert code == 1
    out = capsys.readouterr().out
    assert "[SEDANG] Content-Security-Policy tidak ada" in out
    assert "keyakinan: tinggi" in out
    assert "saran :" in out
    assert "HTTP polos" in out  # HSTS dilewati lewat HTTP, dan itu dilaporkan


def test_findings_are_ordered_by_severity(capsys):
    main(["headers", "http://127.0.0.1:3000/"], make_fetcher=factory(reply(BARE)))
    out = capsys.readouterr().out
    assert out.index("[SEDANG]") < out.index("[RENDAH]")


def test_redirect_chain_is_shown(capsys):
    queue = [httpx.Response(302, headers={"location": "/b"}), httpx.Response(200, headers=GOOD)]

    def handler(request):
        return queue.pop(0)

    main(["headers", "https://127.0.0.1:3000/a"], make_fetcher=factory(handler))
    out = capsys.readouterr().out
    assert "Redirect: https://127.0.0.1:3000/a -> https://127.0.0.1:3000/b" in out


def test_json_output_is_pure_json_on_stdout(capsys):
    code = main(["headers", "--json", "http://127.0.0.1:3000/"], make_fetcher=factory(reply(BARE)))
    assert code == 1
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["status"] == 200
    assert {"csp-missing", "nosniff-missing"} <= {f["id"] for f in data["findings"]}
    assert data["skipped"]
    assert captured.err == ""


# ---- pagar lingkup ----


@pytest.mark.parametrize(
    "url",
    [
        "http://evil.example/",
        "http://10.239.146.11:3000/",
        "http://localhost.evil.example/",
        "http://127.0.0.1@evil.example/",
        "file:///etc/passwd",
    ],
)
def test_out_of_scope_exits_two_without_sending_a_request(url, capsys):
    seen = []
    code = main(["headers", url], make_fetcher=factory(reply(GOOD, seen=seen)))
    assert code == 2
    assert seen == []
    captured = capsys.readouterr()
    assert captured.err.startswith("web-scout:")
    assert captured.out == ""


def test_allow_without_ownership_flag_is_refused(capsys):
    seen = []
    argv = ["headers", "--allow", "lab.example.com", "https://lab.example.com/"]
    assert main(argv, make_fetcher=factory(reply(GOOD, seen=seen))) == 2
    assert seen == []
    assert "--i-own-this" in capsys.readouterr().err


def test_ownership_flag_without_allow_is_refused(capsys):
    seen = []
    argv = ["headers", "--i-own-this", "http://127.0.0.1:3000/"]
    assert main(argv, make_fetcher=factory(reply(GOOD, seen=seen))) == 2
    assert seen == []
    assert "tanpa --allow" in capsys.readouterr().err


def test_allowed_host_with_ownership_flag_is_scanned(capsys):
    argv = ["headers", "--allow", "lab.example.com", "--i-own-this", "https://lab.example.com/"]
    code = main(argv, make_fetcher=factory(reply(GOOD), resolver=lambda host: ["10.0.0.5"]))
    assert code == 0
    assert "https://lab.example.com/" in capsys.readouterr().out


def test_redirect_out_of_scope_is_reported_not_followed(capsys):
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(302, headers={"location": "http://169.254.169.254/latest/"})

    assert main(["headers", "http://127.0.0.1:3000/"], make_fetcher=factory(handler)) == 2
    assert len(seen) == 1
    assert "luar lingkup" in capsys.readouterr().err


# ---- galat jaringan ----


def test_network_error_exits_two_without_leaking_details(capsys):
    def handler(request):
        raise httpx.ConnectError("rahasia-internal")

    assert main(["headers", "http://127.0.0.1:3000/"], make_fetcher=factory(handler)) == 2
    err = capsys.readouterr().err
    assert "gagal terhubung" in err
    assert "rahasia-internal" not in err


# ---- penggunaan ----


def test_no_subcommand_is_a_usage_error():
    with pytest.raises(SystemExit) as info:
        main([])
    assert info.value.code == 2


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as info:
        main(["--version"])
    assert info.value.code == 0
    assert "web-scout" in capsys.readouterr().out
