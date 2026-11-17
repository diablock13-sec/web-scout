import httpx
import pytest

from web_scout.client import Fetcher, Response
from web_scout.cors import (
    FOREIGN_ORIGIN,
    NULL_ORIGIN,
    ProbeResult,
    check_cors,
    run_probes,
)
from web_scout.headers import LEVELS
from web_scout.scope import Scope, ScopeError

URL = "http://localhost:3000/"
LOOKALIKE = "https://localhost.evil.example"


def pr(label, origin, acao=None, creds=None, vary=None, status=200):
    headers = []
    if acao is not None:
        headers.append(("access-control-allow-origin", acao))
    if creds is not None:
        headers.append(("access-control-allow-credentials", creds))
    if vary is not None:
        headers.append(("vary", vary))
    return ProbeResult(label, origin, Response(URL, status, httpx.Headers(headers)))


def probes(**per_label):
    """Empat hasil uji standar. per_label: label -> kwargs untuk pr(acao=..., creds=...)."""
    origins = {"baseline": None, "asing": FOREIGN_ORIGIN, "null": NULL_ORIGIN, "mirip": LOOKALIKE}
    return [pr(label, origin, **per_label.get(label, {})) for label, origin in origins.items()]


def reflecting(creds=None, vary="Origin", labels=("asing", "null", "mirip")):
    origins = {"asing": FOREIGN_ORIGIN, "null": NULL_ORIGIN, "mirip": LOOKALIKE}
    return {
        label: {"acao": origins[label], "creds": creds, "vary": vary} for label in labels
    }


def ids(report):
    return {f.id for f in report.findings}


def one(report, finding_id):
    matches = [f for f in report.findings if f.id == finding_id]
    assert len(matches) == 1, f"{finding_id}: ditemukan {len(matches)}"
    return matches[0]


# ---- tanpa CORS ----


def test_no_cors_headers_means_no_findings_and_says_so():
    report = check_cors(probes())
    assert report.findings == []
    assert any("tidak ada header CORS" in s for s in report.skipped)
    assert any("preflight" in s for s in report.skipped)


# ---- wildcard ----


def test_wildcard_without_credentials_is_low_severity():
    finding = one(check_cors(probes(baseline={"acao": "*"})), "cors-wildcard")
    assert (finding.severity, finding.confidence) == ("rendah", "sedang")


def test_wildcard_with_credentials_is_flagged_as_misconfiguration():
    finding = one(check_cors(probes(baseline={"acao": "*", "creds": "true"})), "cors-wildcard-credentials")
    assert finding.severity == "sedang"


def test_credentials_value_must_be_exactly_true():
    report = check_cors(probes(baseline={"acao": "*", "creds": "True"}))
    assert ids(report) == {"cors-wildcard"}


# ---- pantulan ----


def test_reflected_arbitrary_origin_with_credentials_is_high():
    report = check_cors(probes(**reflecting(creds="true")))
    finding = one(report, "cors-reflect-credentials")
    assert (finding.severity, finding.confidence) == ("tinggi", "tinggi")
    assert "cors-reflect" not in ids(report)  # tidak digandakan


def test_reflected_arbitrary_origin_without_credentials_is_medium():
    finding = one(check_cors(probes(**reflecting())), "cors-reflect")
    assert finding.severity == "sedang"


def test_null_origin_with_credentials_is_high_even_when_other_origins_are_rejected():
    report = check_cors(probes(null={"acao": "null", "creds": "true", "vary": "Origin"}))
    assert ids(report) == {"cors-null-credentials"}
    assert one(report, "cors-null-credentials").severity == "tinggi"


def test_lookalike_only_reflection_means_weak_origin_validation():
    report = check_cors(probes(mirip={"acao": LOOKALIKE, "creds": "true", "vary": "Origin"}))
    assert ids(report) == {"cors-lookalike-credentials"}


def test_lookalike_is_suppressed_when_any_origin_is_reflected():
    report = check_cors(probes(**reflecting()))
    assert "cors-lookalike" not in ids(report)
    assert "cors-reflect" in ids(report)


def test_fixed_allowlisted_origin_is_not_a_finding():
    fixed = {"acao": "https://app.example.com", "creds": "true", "vary": "Origin"}
    report = check_cors(probes(**{label: fixed for label in ("baseline", "asing", "null", "mirip")}))
    assert report.findings == []


# ---- Vary ----


@pytest.mark.parametrize("vary", ["Origin", "Accept-Encoding, Origin", "origin", "*"])
def test_vary_origin_present_is_fine(vary):
    assert "cors-vary-missing" not in ids(check_cors(probes(**reflecting(vary=vary))))


@pytest.mark.parametrize("vary", [None, "Accept-Encoding"])
def test_reflection_without_vary_origin_is_flagged(vary):
    assert "cors-vary-missing" in ids(check_cors(probes(**reflecting(vary=vary))))


# ---- bentuk temuan ----


def test_findings_are_complete_and_evidence_is_cleaned():
    results = probes(**reflecting(creds="true", vary=None), baseline={"acao": "*\x07"})
    report = check_cors(results)
    assert len(report.findings) >= 3
    for f in report.findings:
        assert f.severity in LEVELS
        assert f.confidence in LEVELS
        assert f.advice.strip()
        assert "\x07" not in f.evidence
        assert f.evidence.startswith(("Origin:", "Vary:"))


# ---- run_probes dengan Fetcher ----


def fetcher(handler):
    return Fetcher(
        Scope(),
        transport=httpx.MockTransport(handler),
        min_interval=0,
        resolver=lambda host: ["127.0.0.1"],
    )


def run(handler, url=URL):
    seen = []

    def wrapped(request):
        seen.append(request.headers.get("origin"))
        return handler(request)

    with fetcher(wrapped) as f:
        return run_probes(f, url), seen


def echo_origin(request):
    origin = request.headers.get("origin")
    headers = [("content-type", "text/html")]
    if origin:
        headers += [
            ("access-control-allow-origin", origin),
            ("access-control-allow-credentials", "true"),
        ]
    return httpx.Response(200, headers=headers)


def test_hostname_target_sends_four_probes_including_lookalike():
    report, seen = run(echo_origin)
    assert seen == [None, FOREIGN_ORIGIN, NULL_ORIGIN, LOOKALIKE]
    assert {"cors-reflect-credentials", "cors-null-credentials"} <= ids(report)


@pytest.mark.parametrize("url", ["http://127.0.0.1:3000/", "http://[::1]:3000/"])
def test_ip_target_skips_lookalike_and_says_so(url):
    report, seen = run(echo_origin, url)
    assert seen == [None, FOREIGN_ORIGIN, NULL_ORIGIN]
    assert any("alamat IP" in s for s in report.skipped)


def test_wildcard_server_is_reported_once():
    def handler(request):
        return httpx.Response(200, headers={"access-control-allow-origin": "*"})

    report, _ = run(handler)
    assert ids(report) == {"cors-wildcard"}


def test_server_without_cors_has_no_findings():
    report, _ = run(lambda request: httpx.Response(200))
    assert report.findings == []


def test_out_of_scope_target_sends_nothing():
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200)

    with fetcher(handler) as f, pytest.raises(ScopeError):
        run_probes(f, "http://evil.example/")
    assert seen == []
