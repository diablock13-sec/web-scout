import httpx
import pytest

from web_scout.client import Response
from web_scout.headers import (
    EVIDENCE_MAX,
    HSTS_MIN_AGE,
    LEVELS,
    check_headers,
    parse_csp,
)

HTTPS = "https://app.example.com/"
HTTP = "http://127.0.0.1:3000/"
GOOD = [
    ("content-type", "text/html; charset=utf-8"),
    ("content-security-policy", "default-src 'self'; frame-ancestors 'none'"),
    ("strict-transport-security", "max-age=31536000; includeSubDomains"),
    ("x-content-type-options", "nosniff"),
]


def resp(headers, url=HTTPS, status=200):
    return Response(url=url, status=status, headers=httpx.Headers(headers))


def without(*names):
    return [(k, v) for k, v in GOOD if k not in names]


def ids(report):
    return {f.id for f in report.findings}


def one(report, finding_id):
    matches = [f for f in report.findings if f.id == finding_id]
    assert len(matches) == 1, f"{finding_id}: ditemukan {len(matches)}"
    return matches[0]


def csp(value, extra=()):
    return [
        ("content-type", "text/html"),
        ("x-content-type-options", "nosniff"),
        ("content-security-policy", value),
        *extra,
    ]


# ---- dasar ----


def test_well_configured_response_has_no_findings():
    report = check_headers(resp(GOOD))
    assert report.findings == []
    assert report.skipped == []


def test_everything_missing_on_https_html():
    report = check_headers(resp([("content-type", "text/html")]))
    assert ids(report) == {"csp-missing", "framing-missing", "nosniff-missing", "hsts-missing"}


def test_every_finding_is_complete_and_valid():
    report = check_headers(
        resp(
            [
                ("content-type", "text/html"),
                ("content-security-policy", "script-src * 'unsafe-inline' 'unsafe-eval'"),
                ("x-frame-options", "ALLOW-FROM https://x.example"),
                ("x-content-type-options", "sniff"),
                ("strict-transport-security", "max-age=1"),
                ("strict-transport-security", "max-age=2"),
            ]
        )
    )
    assert len(report.findings) >= 6
    assert len({f.id for f in report.findings}) == len(report.findings)
    for f in report.findings:
        assert f.severity in LEVELS
        assert f.confidence in LEVELS
        assert f.advice.strip()
        assert f.title.strip()
        assert f.url == HTTPS


# ---- konteks ----


def test_plain_http_skips_hsts_and_says_so():
    report = check_headers(resp(without("strict-transport-security"), url=HTTP))
    assert "hsts-missing" not in ids(report)
    assert any("HTTP polos" in s for s in report.skipped)


def test_non_html_skips_csp_and_framing_but_not_nosniff_or_hsts():
    report = check_headers(resp([("content-type", "application/json")]))
    assert ids(report) == {"nosniff-missing", "hsts-missing"}
    assert any("bukan HTML (application/json)" in s for s in report.skipped)


@pytest.mark.parametrize("status", [301, 302, 307, 204, 304])
def test_bodiless_responses_skip_csp_and_framing(status):
    report = check_headers(resp([("content-type", "text/html")], status=status))
    assert "csp-missing" not in ids(report)
    assert "framing-missing" not in ids(report)
    assert any("tanpa isi" in s for s in report.skipped)
    assert "hsts-missing" in ids(report)  # HSTS pada redirect tetap penting


def test_missing_content_type_still_checks_but_with_lower_confidence():
    report = check_headers(resp([]))
    assert one(report, "csp-missing").confidence == "sedang"  # biasanya tinggi
    assert one(report, "framing-missing").confidence == "rendah"  # biasanya sedang
    assert one(report, "nosniff-missing").confidence == "tinggi"  # tidak bergantung konteks


def test_xhtml_counts_as_html():
    report = check_headers(resp([("content-type", "application/xhtml+xml")]))
    assert "csp-missing" in ids(report)


# ---- CSP ----


def test_report_only_is_flagged_as_not_enforcing():
    report = check_headers(
        resp([("content-type", "text/html"), ("content-security-policy-report-only", "default-src 'self'")])
    )
    assert "csp-report-only" in ids(report)
    assert "csp-missing" not in ids(report)


def test_empty_csp_counts_as_missing():
    report = check_headers(resp(csp("")))
    assert one(report, "csp-missing").evidence == "(kosong)"


@pytest.mark.parametrize(
    ("value", "flagged"),
    [
        ("script-src 'unsafe-inline'", True),
        ("default-src 'self' 'unsafe-inline'", True),
        ("script-src 'unsafe-inline' 'nonce-abc123'", False),
        ("script-src 'unsafe-inline' 'sha256-abc'", False),
        ("script-src 'unsafe-inline' 'strict-dynamic'", False),
        ("script-src 'self'", False),
        ("style-src 'unsafe-inline'; script-src 'self'", False),  # hanya gaya, bukan skrip
        ("Script-Src 'UNSAFE-INLINE'", True),
    ],
)
def test_unsafe_inline(value, flagged):
    assert ("csp-unsafe-inline" in ids(check_headers(resp(csp(value))))) is flagged


def test_unsafe_eval_is_low_severity():
    finding = one(check_headers(resp(csp("script-src 'self' 'unsafe-eval'"))), "csp-unsafe-eval")
    assert finding.severity == "rendah"


@pytest.mark.parametrize("source", ["*", "https:", "http:", "data:"])
def test_loose_script_sources_flagged(source):
    report = check_headers(resp(csp(f"script-src 'self' {source}")))
    assert "csp-wildcard-script-source" in ids(report)


def test_script_src_overrides_default_src():
    report = check_headers(resp(csp("script-src 'self'; default-src *")))
    assert "csp-wildcard-script-source" not in ids(report)


def test_default_src_is_the_fallback_for_scripts():
    assert "csp-wildcard-script-source" in ids(check_headers(resp(csp("default-src *"))))


def test_policy_without_script_restriction_is_flagged():
    assert "csp-unrestricted-scripts" in ids(check_headers(resp(csp("img-src 'self'"))))


def test_weakness_needs_every_policy_to_have_it():
    weak = ("content-security-policy", "script-src 'unsafe-inline'")
    strong = ("content-security-policy", "script-src 'self'")
    only_weak = check_headers(resp(csp("script-src 'unsafe-inline'")))
    mixed = check_headers(resp(csp("script-src 'unsafe-inline'", extra=[strong])))
    both_weak = check_headers(resp(csp("script-src 'unsafe-inline'", extra=[weak])))
    assert "csp-unsafe-inline" in ids(only_weak)
    assert "csp-unsafe-inline" not in ids(mixed)
    assert "csp-unsafe-inline" in ids(both_weak)


def test_comma_separated_policies_are_evaluated_separately():
    report = check_headers(resp(csp("script-src 'unsafe-inline', script-src 'self'")))
    assert "csp-unsafe-inline" not in ids(report)


def test_first_duplicate_directive_wins():
    assert parse_csp("script-src 'self'; script-src *")["script-src"] == ["'self'"]


# ---- perlindungan frame ----


@pytest.mark.parametrize("value", ["DENY", "deny", "SAMEORIGIN", "DENY, DENY"])
def test_valid_x_frame_options_protect(value):
    report = check_headers(resp([*csp("default-src 'self'"), ("x-frame-options", value)]))
    assert not {"framing-missing", "xfo-invalid", "xfo-conflicting"} & ids(report)


def test_frame_ancestors_replaces_x_frame_options():
    report = check_headers(resp(csp("default-src 'self'; frame-ancestors 'self'")))
    assert "framing-missing" not in ids(report)


@pytest.mark.parametrize(
    ("value", "finding_id"),
    [
        ("ALLOW-FROM https://x.example", "xfo-allow-from"),
        ("INVALID", "xfo-invalid"),
        ("", "xfo-invalid"),
        ("DENY, SAMEORIGIN", "xfo-conflicting"),
    ],
)
def test_bad_x_frame_options(value, finding_id):
    report = check_headers(resp([*csp("default-src 'self'"), ("x-frame-options", value)]))
    assert finding_id in ids(report)


def test_permissive_frame_ancestors_is_flagged_and_x_frame_options_does_not_save_it():
    report = check_headers(
        resp([*csp("default-src 'self'; frame-ancestors *"), ("x-frame-options", "DENY")])
    )
    assert "framing-permissive" in ids(report)
    assert "framing-missing" not in ids(report)


def test_one_strict_policy_among_several_is_enough_for_framing():
    strict = ("content-security-policy", "frame-ancestors 'none'")
    report = check_headers(resp(csp("frame-ancestors *", extra=[strict])))
    assert "framing-permissive" not in ids(report)


# ---- X-Content-Type-Options ----


@pytest.mark.parametrize("value", ["nosniff", "NoSniff", " nosniff ", "nosniff, nosniff"])
def test_nosniff_accepted(value):
    report = check_headers(resp([*without("x-content-type-options"), ("x-content-type-options", value)]))
    assert not {"nosniff-missing", "nosniff-invalid"} & ids(report)


@pytest.mark.parametrize("value", ["sniff", "", "no-sniff"])
def test_nosniff_wrong_value(value):
    report = check_headers(resp([*without("x-content-type-options"), ("x-content-type-options", value)]))
    assert "nosniff-invalid" in ids(report)


# ---- HSTS ----


def hsts(value):
    return [*without("strict-transport-security"), ("strict-transport-security", value)]


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("max-age=31536000", set()),
        ("max-age=31536000; includeSubDomains; preload", set()),
        ('max-age="31536000"', set()),
        ("Max-Age=31536000", set()),
        (f"max-age={HSTS_MIN_AGE}", set()),
        (f"max-age={HSTS_MIN_AGE - 1}", {"hsts-short"}),
        ("max-age=100", {"hsts-short"}),
        ("max-age=0", {"hsts-disabled"}),
        ("max-age=abc", {"hsts-invalid"}),
        ("max-age=", {"hsts-invalid"}),
        ("includeSubDomains", {"hsts-invalid"}),
        ("max-age=1; max-age=2", {"hsts-invalid"}),
        ("max-age=-5", {"hsts-invalid"}),
        ("max-age=99999999999999999999", {"hsts-invalid"}),
    ],
)
def test_hsts_values(value, expected):
    assert ids(check_headers(resp(hsts(value)))) == expected


def test_only_the_first_hsts_header_is_evaluated_and_duplicates_are_flagged():
    headers = [*hsts("max-age=0"), ("strict-transport-security", "max-age=31536000")]
    assert ids(check_headers(resp(headers))) == {"hsts-disabled", "hsts-multiple"}


# ---- bukti ----


def test_evidence_is_cleaned_and_truncated():
    noisy = [*without("x-content-type-options"), ("x-content-type-options", "bad\x07value")]
    assert one(check_headers(resp(noisy)), "nosniff-invalid").evidence == "bad?value"
    long = [*without("x-content-type-options"), ("x-content-type-options", "x" * 500)]
    assert len(one(check_headers(resp(long)), "nosniff-invalid").evidence) == EVIDENCE_MAX + 3
