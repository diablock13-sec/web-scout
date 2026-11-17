"""Pemeriksa header keamanan HTTP. Murni: menerima Response dari client.py, tanpa I/O.

Tiap temuan membawa tingkat keparahan (seberapa buruk kalau benar), tingkat keyakinan
(seberapa pasti pemeriksaan ini benar), dan saran perbaikan. Pemeriksaan header jarang
menghasilkan keparahan 'tinggi': kelemahan di sini memperlemah pertahanan berlapis,
bukan membuka celah sendiri.
"""

import re
from dataclasses import dataclass

from web_scout.client import Response

LEVELS = ("rendah", "sedang", "tinggi")
HSTS_MIN_AGE = 15_768_000  # enam bulan
HSTS_RECOMMENDED = 31_536_000  # satu tahun
EVIDENCE_MAX = 200
NO_BODY_STATUSES = frozenset({204, 304})
HTML_TYPES = frozenset({"text/html", "application/xhtml+xml"})
LOOSE_SOURCES = frozenset({"*", "http:", "https:", "data:"})
LOOSE_ANCESTORS = frozenset({"*", "http:", "https:"})
STRICT_DYNAMIC = "'strict-dynamic'"
INTEGRITY_PREFIXES = ("'nonce-", "'sha256-", "'sha384-", "'sha512-")

ADVICE_CSP_MISSING = (
    "Tambahkan Content-Security-Policy. Mulai dari yang ketat, misalnya "
    "\"default-src 'self'; frame-ancestors 'none'\", lalu longgarkan seperlunya. "
    "Uji dulu dengan Content-Security-Policy-Report-Only agar tidak merusak halaman."
)
ADVICE_CSP_REPORT_ONLY = (
    "Mode Report-Only hanya melaporkan, tidak memblokir. Setelah laporan bersih, "
    "pindahkan kebijakan yang sama ke header Content-Security-Policy."
)
ADVICE_CSP_UNRESTRICTED = (
    "Kebijakan tidak membatasi skrip (tidak ada script-src dan default-src). "
    "Tambahkan default-src 'self' atau script-src yang menyebut sumber skrip secara eksplisit."
)
ADVICE_CSP_INLINE = (
    "'unsafe-inline' membuat CSP tidak menghentikan XSS. Pindahkan skrip inline ke file, "
    "atau pakai nonce atau hash per skrip (browser mengabaikan 'unsafe-inline' kalau ada)."
)
ADVICE_CSP_EVAL = (
    "'unsafe-eval' mengizinkan eval() dan sejenisnya. Hilangkan pemakaian eval di kode "
    "dan pustaka, lalu buang 'unsafe-eval'."
)
ADVICE_CSP_WILDCARD = (
    "Sumber skrip terlalu luas ('*', 'http:', 'https:', atau 'data:'). Sebut host yang "
    "dipercaya secara eksplisit, atau pakai nonce dengan 'strict-dynamic'."
)
ADVICE_FRAMING_MISSING = (
    "Tambahkan \"Content-Security-Policy: frame-ancestors 'none'\" (atau 'self'), dan "
    "\"X-Frame-Options: DENY\" (atau SAMEORIGIN) untuk browser lama. Berlaku untuk halaman "
    "HTML; endpoint API tidak terdampak."
)
ADVICE_FRAMING_PERMISSIVE = (
    "frame-ancestors terlalu longgar. Pakai 'none' atau 'self', atau sebut host yang "
    "dipercaya. Kalau frame-ancestors ada, X-Frame-Options diabaikan browser modern."
)
ADVICE_XFO_ALLOW_FROM = (
    "ALLOW-FROM sudah tidak didukung browser modern, jadi tidak melindungi apa pun. "
    "Pakai Content-Security-Policy: frame-ancestors."
)
ADVICE_XFO_INVALID = (
    "Nilai X-Frame-Options hanya boleh DENY atau SAMEORIGIN. Nilai lain diabaikan browser."
)
ADVICE_XFO_CONFLICTING = (
    "Beberapa nilai X-Frame-Options yang saling bertentangan membuat browser mengabaikannya. "
    "Kirim satu header dengan satu nilai."
)
ADVICE_NOSNIFF_MISSING = (
    "Tambahkan \"X-Content-Type-Options: nosniff\" agar browser tidak menebak tipe konten "
    "(mencegah file yang diunggah dieksekusi sebagai skrip)."
)
ADVICE_NOSNIFF_INVALID = "Satu-satunya nilai yang sah adalah: nosniff."
ADVICE_HSTS_MISSING = (
    "Tambahkan \"Strict-Transport-Security: max-age=31536000; includeSubDomains\". "
    "Naikkan ke 'preload' hanya setelah yakin seluruh subdomain mendukung HTTPS."
)
ADVICE_HSTS_INVALID = (
    "Header Strict-Transport-Security harus memuat tepat satu max-age berupa bilangan bulat, "
    "misalnya max-age=31536000."
)
ADVICE_HSTS_DISABLED = "max-age=0 mematikan HSTS. Pakai max-age=31536000 atau lebih."
ADVICE_HSTS_SHORT = (
    "max-age terlalu pendek untuk melindungi pengunjung yang jarang datang. "
    "Pakai minimal 15768000 (enam bulan), idealnya 31536000 (satu tahun)."
)
ADVICE_HSTS_MULTIPLE = (
    "Browser hanya memakai header Strict-Transport-Security yang pertama. "
    "Kirim satu header saja."
)


@dataclass(frozen=True)
class Finding:
    id: str  # stabil, dipakai untuk menyaring atau membandingkan antar-pindai
    title: str
    severity: str  # rendah | sedang | tinggi
    confidence: str  # rendah | sedang | tinggi
    url: str
    evidence: str
    advice: str


@dataclass(frozen=True)
class HeaderReport:
    findings: list[Finding]
    skipped: list[str]  # apa yang TIDAK diperiksa, beserta alasannya


def _clean(value: str) -> str:
    text = "".join(ch if ch.isprintable() else "?" for ch in value)
    return text if len(text) <= EVIDENCE_MAX else text[:EVIDENCE_MAX] + "..."


def _lower(level: str) -> str:
    return LEVELS[max(LEVELS.index(level) - 1, 0)]


@dataclass(frozen=True)
class _Ctx:
    url: str
    uncertain: bool = False  # konteks tidak jelas: keyakinan diturunkan satu tingkat

    def finding(
        self,
        id_: str,
        title: str,
        severity: str,
        confidence: str,
        evidence: str,
        advice: str,
    ) -> Finding:
        if self.uncertain:
            confidence = _lower(confidence)
        return Finding(id_, title, severity, confidence, self.url, _clean(evidence), advice)


# ---- CSP ----


def parse_csp(value: str) -> dict[str, list[str]]:
    """Satu kebijakan jadi {direktif: [sumber]}. Direktif ganda: yang pertama berlaku."""
    policy: dict[str, list[str]] = {}
    for raw in value.split(";"):
        parts = raw.lower().split()
        if parts and parts[0] not in policy:
            policy[parts[0]] = parts[1:]
    return policy


def _csp_policies(values: list[str]) -> list[dict[str, list[str]]]:
    policies = []
    for value in values:
        for chunk in value.split(","):  # satu header boleh memuat beberapa kebijakan
            policy = parse_csp(chunk)
            if policy:
                policies.append(policy)
    return policies


def _script_sources(policy: dict[str, list[str]]) -> list[str] | None:
    sources = policy.get("script-src")
    return policy.get("default-src") if sources is None else sources


def _has_unsafe_inline(policy: dict[str, list[str]]) -> bool:
    sources = _script_sources(policy) or []
    if "'unsafe-inline'" not in sources:
        return False
    # Browser mengabaikan 'unsafe-inline' kalau ada nonce, hash, atau strict-dynamic.
    protected = STRICT_DYNAMIC in sources or any(
        s.startswith(INTEGRITY_PREFIXES) for s in sources
    )
    return not protected


def _check_csp(
    headers, policies: list[dict[str, list[str]]], ctx: _Ctx
) -> list[Finding]:
    enforcing = headers.get_list("content-security-policy")
    if not policies:
        report_only = headers.get_list("content-security-policy-report-only")
        if report_only:
            return [
                ctx.finding(
                    "csp-report-only",
                    "CSP hanya berupa Report-Only, tidak memblokir apa pun",
                    "sedang", "tinggi", report_only[0], ADVICE_CSP_REPORT_ONLY,
                )
            ]  # fmt: skip
        evidence = "(kosong)" if enforcing else "(header tidak ada)"
        return [
            ctx.finding(
                "csp-missing", "Content-Security-Policy tidak ada",
                "sedang", "tinggi", evidence, ADVICE_CSP_MISSING,
            )
        ]  # fmt: skip

    evidence = enforcing[0]

    def weak(predicate) -> bool:  # kelemahan dilaporkan hanya kalau SEMUA kebijakan memilikinya
        return all(predicate(p) for p in policies)

    checks = (
        (
            lambda p: _script_sources(p) is None,
            "csp-unrestricted-scripts", "CSP tidak membatasi skrip",
            "sedang", "tinggi", ADVICE_CSP_UNRESTRICTED,
        ),
        (
            _has_unsafe_inline,
            "csp-unsafe-inline", "CSP mengizinkan skrip inline ('unsafe-inline')",
            "sedang", "tinggi", ADVICE_CSP_INLINE,
        ),
        (
            lambda p: "'unsafe-eval'" in (_script_sources(p) or []),
            "csp-unsafe-eval", "CSP mengizinkan eval ('unsafe-eval')",
            "rendah", "tinggi", ADVICE_CSP_EVAL,
        ),
        (
            lambda p: any(s in LOOSE_SOURCES for s in (_script_sources(p) or [])),
            "csp-wildcard-script-source", "CSP mengizinkan sumber skrip yang terlalu luas",
            "sedang", "tinggi", ADVICE_CSP_WILDCARD,
        ),
    )  # fmt: skip
    return [
        ctx.finding(id_, title, severity, confidence, evidence, advice)
        for predicate, id_, title, severity, confidence, advice in checks
        if weak(predicate)
    ]


# ---- perlindungan frame ----


def _check_framing(
    headers, policies: list[dict[str, list[str]]], ctx: _Ctx
) -> list[Finding]:
    ancestors = [p["frame-ancestors"] for p in policies if "frame-ancestors" in p]
    if any(not any(s in LOOSE_ANCESTORS for s in sources) for sources in ancestors):
        return []  # frame-ancestors yang ketat melindungi, dan menggantikan X-Frame-Options
    if ancestors:
        return [
            ctx.finding(
                "framing-permissive", "frame-ancestors terlalu longgar",
                "sedang", "tinggi", " ".join(ancestors[0]), ADVICE_FRAMING_PERMISSIVE,
            )
        ]  # fmt: skip

    raw = headers.get("x-frame-options")
    if raw is None:
        return [
            ctx.finding(
                "framing-missing", "Halaman bisa dibingkai (risiko clickjacking)",
                "sedang", "sedang", "(header tidak ada)", ADVICE_FRAMING_MISSING,
            )
        ]  # fmt: skip
    tokens = {t.strip().lower() for t in raw.split(",")}
    if len(tokens) > 1:
        return [
            ctx.finding(
                "xfo-conflicting", "X-Frame-Options berisi nilai yang bertentangan",
                "sedang", "sedang", raw, ADVICE_XFO_CONFLICTING,
            )
        ]  # fmt: skip
    token = tokens.pop()
    if token in {"deny", "sameorigin"}:
        return []
    if token.startswith("allow-from"):
        return [
            ctx.finding(
                "xfo-allow-from", "X-Frame-Options ALLOW-FROM tidak didukung browser",
                "sedang", "tinggi", raw, ADVICE_XFO_ALLOW_FROM,
            )
        ]  # fmt: skip
    return [
        ctx.finding(
            "xfo-invalid", "X-Frame-Options berisi nilai yang tidak sah",
            "sedang", "tinggi", raw, ADVICE_XFO_INVALID,
        )
    ]  # fmt: skip


# ---- X-Content-Type-Options ----


def _check_nosniff(headers, ctx: _Ctx) -> list[Finding]:
    raw = headers.get("x-content-type-options")
    if raw is None:
        return [
            ctx.finding(
                "nosniff-missing", "X-Content-Type-Options tidak ada",
                "rendah", "tinggi", "(header tidak ada)", ADVICE_NOSNIFF_MISSING,
            )
        ]  # fmt: skip
    if raw.split(",")[0].strip().lower() != "nosniff":
        return [
            ctx.finding(
                "nosniff-invalid", "X-Content-Type-Options bukan 'nosniff'",
                "rendah", "tinggi", raw, ADVICE_NOSNIFF_INVALID,
            )
        ]  # fmt: skip
    return []


# ---- HSTS ----


def _hsts_max_age(value: str) -> int | None:
    """max-age dari satu header HSTS, atau None kalau tidak sah (hilang, ganda, bukan angka)."""
    ages = []
    for directive in value.split(";"):
        name, _, raw = directive.strip().partition("=")
        if name.strip().lower() == "max-age":
            ages.append(raw.strip().strip('"'))
    if len(ages) != 1 or not re.fullmatch(r"[0-9]{1,12}", ages[0]):
        return None
    return int(ages[0])


def _check_hsts(headers, ctx: _Ctx) -> list[Finding]:
    values = headers.get_list("strict-transport-security")
    if not values:
        return [
            ctx.finding(
                "hsts-missing", "Strict-Transport-Security tidak ada",
                "sedang", "tinggi", "(header tidak ada)", ADVICE_HSTS_MISSING,
            )
        ]  # fmt: skip
    findings = []
    first = values[0]  # RFC 6797: hanya header pertama yang diproses
    max_age = _hsts_max_age(first)
    if max_age is None:
        findings.append(
            ctx.finding(
                "hsts-invalid", "Header HSTS tidak sah",
                "rendah", "sedang", first, ADVICE_HSTS_INVALID,
            )
        )  # fmt: skip
    elif max_age == 0:
        findings.append(
            ctx.finding(
                "hsts-disabled", "HSTS dimatikan (max-age=0)",
                "sedang", "tinggi", first, ADVICE_HSTS_DISABLED,
            )
        )  # fmt: skip
    elif max_age < HSTS_MIN_AGE:
        findings.append(
            ctx.finding(
                "hsts-short", f"HSTS max-age terlalu pendek ({max_age} detik)",
                "rendah", "tinggi", first, ADVICE_HSTS_SHORT,
            )
        )  # fmt: skip
    if len(values) > 1:
        findings.append(
            ctx.finding(
                "hsts-multiple", "Beberapa header HSTS dikirim",
                "rendah", "sedang", " | ".join(values), ADVICE_HSTS_MULTIPLE,
            )
        )  # fmt: skip
    return findings


# ---- pintu masuk ----


def _document_context(response: Response) -> tuple[bool, bool, str]:
    """(berlaku, tidak pasti, alasan dilewati) untuk pemeriksaan yang khusus dokumen HTML."""
    if 300 <= response.status < 400 or response.status in NO_BODY_STATUSES:
        return False, False, f"respons tanpa isi (status {response.status})"
    media = response.headers.get("content-type", "").split(";")[0].strip().lower()
    if not media:
        return True, True, ""
    if media in HTML_TYPES:
        return True, False, ""
    return False, False, f"respons bukan HTML ({_clean(media)})"


def check_headers(response: Response) -> HeaderReport:
    headers = response.headers
    findings: list[Finding] = []
    skipped: list[str] = []

    applies, uncertain, reason = _document_context(response)
    if applies:
        ctx = _Ctx(response.url, uncertain)
        policies = _csp_policies(headers.get_list("content-security-policy"))
        findings += _check_csp(headers, policies, ctx)
        findings += _check_framing(headers, policies, ctx)
    else:
        skipped.append(f"CSP dan perlindungan frame tidak diperiksa: {reason}")

    plain = _Ctx(response.url)
    findings += _check_nosniff(headers, plain)
    if response.url.startswith("https://"):
        findings += _check_hsts(headers, plain)
    else:
        skipped.append(
            "HSTS tidak diperiksa: respons lewat HTTP polos (HSTS hanya berlaku lewat HTTPS)"
        )
    return HeaderReport(findings, skipped)
