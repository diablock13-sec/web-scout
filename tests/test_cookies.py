import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest

from web_scout.client import Fetcher, Response
from web_scout.cookies import check_cookies, classify, parse_set_cookie
from web_scout.headers import LEVELS
from web_scout.scope import Scope

HTTPS = "https://app.example.com/"
HTTP = "http://127.0.0.1:3000/"
SECRET = "TOPSECRETVALUE"


def resp(*cookies, url=HTTPS, history=()):
    headers = [("set-cookie", c) for c in cookies]
    return Response(url=url, status=200, headers=httpx.Headers(headers), history=tuple(history))


def ids(report):
    return {f.id for f in report.findings}


def one(report, finding_id):
    matches = [f for f in report.findings if f.id == finding_id]
    assert len(matches) == 1, f"{finding_id}: ditemukan {len(matches)}"
    return matches[0]


GOOD = "session=abc; Secure; HttpOnly; SameSite=Lax; Path=/"


# ---- parsing ----


def test_parse_drops_the_cookie_value():
    cookie = parse_set_cookie(f"sid={SECRET}; Secure; HttpOnly; SameSite=Lax; Path=/")
    assert cookie.name == "sid"
    assert cookie.attributes == {
        "secure": "",
        "httponly": "",
        "samesite": "Lax",
        "path": "/",
    }
    assert SECRET not in repr(cookie)


def test_parse_is_case_insensitive_and_last_attribute_wins():
    cookie = parse_set_cookie("a=1; samesite=lax; SameSite=Strict; SECURE")
    assert cookie.attributes["samesite"] == "Strict"
    assert cookie.secure


@pytest.mark.parametrize("line", ["", "tanpa-nilai", "=nilai", "  =x; Secure", ";Secure"])
def test_parse_unreadable_lines_return_none(line):
    assert parse_set_cookie(line) is None


def test_parse_value_containing_equals_and_quotes():
    cookie = parse_set_cookie('a="x=y"; Secure')
    assert cookie.name == "a"
    assert cookie.secure


@pytest.mark.parametrize(
    ("name", "kind"),
    [
        ("sessionid", "sensitif"),
        ("PHPSESSID", "sensitif"),
        ("connect.sid", "sensitif"),
        ("sid", "sensitif"),
        ("authToken", "sensitif"),
        ("jwt", "sensitif"),
        ("remember_me", "sensitif"),
        ("XSRF-TOKEN", "csrf"),
        ("csrf_token", "csrf"),
        ("theme", "biasa"),
        ("language", "biasa"),
        ("inside", "biasa"),  # 'sid' di tengah kata bukan cookie sesi
        ("author", "biasa"),  # 'auth' di awal kata lain
    ],
)
def test_classify(name, kind):
    assert classify(name) == kind


# ---- cookie baik dan tanpa cookie ----


def test_well_configured_cookie_has_no_findings():
    report = check_cookies(resp(GOOD))
    assert report.findings == []
    assert report.cookies_seen == 1


def test_no_set_cookie_header_says_so():
    report = check_cookies(resp())
    assert report.findings == []
    assert report.cookies_seen == 0
    assert any("tidak ada Set-Cookie" in s for s in report.skipped)
    assert any("JavaScript" in s for s in report.skipped)


# ---- keparahan mengikuti jenis cookie ----


def test_sensitive_cookie_with_no_flags_over_https():
    report = check_cookies(resp(f"sessionid={SECRET}"))
    assert ids(report) == {"cookie-no-secure", "cookie-no-httponly", "cookie-no-samesite"}
    assert one(report, "cookie-no-secure").severity == "sedang"
    assert one(report, "cookie-no-httponly").severity == "sedang"
    assert one(report, "cookie-no-samesite").severity == "rendah"
    assert one(report, "cookie-no-samesite").confidence == "sedang"


def test_ordinary_cookie_gets_lower_severity_and_confidence():
    report = check_cookies(resp("theme=dark"))
    assert one(report, "cookie-no-secure").severity == "rendah"
    httponly = one(report, "cookie-no-httponly")
    assert (httponly.severity, httponly.confidence) == ("rendah", "rendah")
    assert one(report, "cookie-no-samesite").confidence == "rendah"


def test_csrf_cookie_is_exempt_from_httponly():
    report = check_cookies(resp("XSRF-TOKEN=abc; Secure; SameSite=Lax"))
    assert report.findings == []


# ---- HTTP polos ----


def test_secure_is_not_judged_over_plain_http_and_says_so():
    report = check_cookies(resp(f"sessionid={SECRET}", url=HTTP))
    assert ids(report) == {"cookie-no-httponly", "cookie-no-samesite"}
    assert any("Secure tidak dinilai" in s for s in report.skipped)


# ---- SameSite ----


def test_samesite_none_without_secure_is_rejected_by_browsers():
    report = check_cookies(resp("a=1; HttpOnly; SameSite=None", url=HTTP))
    finding = one(report, "cookie-samesite-none-insecure")
    assert (finding.severity, finding.confidence) == ("sedang", "tinggi")


def test_samesite_none_with_secure_is_flagged_only_for_sensitive_cookies():
    sensitive = check_cookies(resp("sessionid=1; Secure; HttpOnly; SameSite=None"))
    ordinary = check_cookies(resp("theme=1; Secure; HttpOnly; SameSite=None"))
    assert ids(sensitive) == {"cookie-samesite-none"}
    assert ordinary.findings == []


@pytest.mark.parametrize("value", ["Maybe", "", "lax strict"])
def test_invalid_samesite_value(value):
    report = check_cookies(resp(f"a=1; Secure; HttpOnly; SameSite={value}"))
    assert ids(report) == {"cookie-samesite-invalid"}


@pytest.mark.parametrize("value", ["lax", "LAX", "Strict", "strict"])
def test_valid_samesite_values_in_any_case(value):
    assert check_cookies(resp(f"a=1; Secure; HttpOnly; SameSite={value}")).findings == []


# ---- awalan ----


def test_valid_host_prefix_cookie_passes():
    report = check_cookies(resp("__Host-sid=1; Secure; HttpOnly; SameSite=Lax; Path=/"))
    assert report.findings == []


@pytest.mark.parametrize(
    "line",
    [
        "__Host-sid=1; Secure; HttpOnly; SameSite=Lax; Path=/; Domain=example.com",
        "__Host-sid=1; Secure; HttpOnly; SameSite=Lax",
        "__Host-sid=1; Secure; HttpOnly; SameSite=Lax; Path=/app",
        "__Host-sid=1; HttpOnly; SameSite=Lax; Path=/",
        "__host-sid=1; HttpOnly; SameSite=Lax; Path=/",
    ],
)
def test_host_prefix_violations(line):
    report = check_cookies(resp(line))
    assert ids(report) == {"cookie-prefix-invalid"}  # tidak digandakan dengan 'no-secure'


def test_secure_prefix_without_secure_is_flagged_once():
    report = check_cookies(resp("__Secure-sid=1; HttpOnly; SameSite=Lax"))
    assert ids(report) == {"cookie-prefix-invalid"}


def test_secure_prefix_with_secure_passes():
    assert check_cookies(resp("__Secure-sid=1; Secure; HttpOnly; SameSite=Lax")).findings == []


# ---- nilai cookie tidak pernah bocor ----


def test_cookie_value_never_appears_anywhere_in_the_report():
    lines = [f"sessionid={SECRET}", f"theme={SECRET}; Secure", f"__Host-x={SECRET}"]
    report = check_cookies(resp(*lines))
    assert report.findings
    everything = repr(report)
    assert SECRET not in everything


def test_every_finding_is_complete_and_valid():
    report = check_cookies(resp("sessionid=1", "a=1; SameSite=None", "__Host-b=1"))
    assert report.findings
    for f in report.findings:
        assert f.severity in LEVELS
        assert f.confidence in LEVELS
        assert f.advice.strip()
        assert f.title.strip()
        assert f.url == HTTPS


def test_control_characters_in_names_are_neutralised():
    report = check_cookies(resp("a\x07\x1bb=1"))
    for f in report.findings:
        assert "\x07" not in f.evidence
        assert "\x1b" not in f.evidence
    assert "a??b" in report.findings[0].evidence


def test_long_cookie_name_is_truncated():
    report = check_cookies(resp("n" * 500 + "=1"))
    assert all(len(f.evidence) < 260 for f in report.findings)


# ---- beberapa cookie, redirect, baris rusak ----


def test_each_cookie_is_judged_separately():
    report = check_cookies(resp(GOOD, "theme=dark"))
    assert report.cookies_seen == 2
    assert all("'theme'" in f.evidence for f in report.findings)
    assert report.findings


def test_redirect_hops_are_reported_as_not_checked():
    report = check_cookies(resp(GOOD, history=("https://app.example.com/login",)))
    assert any("1 respons redirect" in s for s in report.skipped)


def test_unreadable_lines_are_counted_and_skipped():
    report = check_cookies(resp(GOOD, "bukan-cookie", "=x"))
    assert report.cookies_seen == 1
    assert any("2 header Set-Cookie tidak bisa dibaca" in s for s in report.skipped)


# ---- lewat socket sungguhan ----


def test_two_real_set_cookie_headers_survive_a_real_connection():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Set-Cookie", f"sessionid={SECRET}; Path=/")
            self.send_header("Set-Cookie", "theme=dark; Path=/; Secure; HttpOnly; SameSite=Lax")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *_args):
            return None

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with Fetcher(Scope(), min_interval=0) as f:
            response = f.get(f"http://127.0.0.1:{server.server_address[1]}/")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    report = check_cookies(response)
    assert report.cookies_seen == 2
    assert "cookie-no-httponly" in ids(report)
    assert any("'sessionid'" in f.evidence for f in report.findings)
    assert SECRET not in repr(report)
