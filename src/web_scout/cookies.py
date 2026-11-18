"""Pemeriksa flag cookie: Secure, HttpOnly, SameSite, dan awalan __Host- / __Secure-.

Murni: menerima Response dari client.py, tanpa I/O. NILAI cookie tidak pernah disimpan,
dicetak, atau masuk bukti: hanya nama dan nama atribut, karena nilainya bisa berupa
sesi yang masih berlaku (struktur Cookie memang tidak punya kolom nilai).

Batas: hanya Set-Cookie pada respons ini. Cookie yang diatur lewat JavaScript, setelah
login, atau pada respons redirect di tengah rantai tidak terlihat. Masa berlaku dan
cakupan (Domain, Path) tidak dinilai.
"""

import re
from dataclasses import dataclass

from web_scout.client import Response
from web_scout.headers import EVIDENCE_MAX, Finding

SAMESITE_VALUES = frozenset({"strict", "lax", "none"})
SENSITIVE_SUBSTRINGS = (
    "sess", "token", "jwt", "login", "credential", "remember", "passw", "secret",
)  # fmt: skip
SENSITIVE_WORDS = re.compile(r"(?:^|[^a-z])(?:sid|auth)(?:[^a-z]|$)")
CSRF = re.compile(r"csrf|xsrf")
KNOWN_ATTRIBUTES = {
    "secure": "Secure",
    "httponly": "HttpOnly",
    "samesite": "SameSite",
    "path": "Path",
    "domain": "Domain",
    "max-age": "Max-Age",
    "expires": "Expires",
    "partitioned": "Partitioned",
}

SCOPE_NOTE = (
    "hanya Set-Cookie pada respons ini yang dinilai; cookie yang diatur lewat JavaScript "
    "atau setelah login tidak terlihat, dan masa berlaku serta Domain dan Path tidak dinilai"
)
ADVICE_SECURE = (
    "Tambahkan atribut Secure agar cookie tidak ikut terkirim lewat HTTP polos "
    "(bisa disadap di jaringan yang tidak tepercaya)."
)
ADVICE_HTTPONLY = (
    "Tambahkan HttpOnly agar JavaScript tidak bisa membaca cookie (membatasi dampak XSS). "
    "Hanya cookie yang memang harus dibaca skrip, seperti token CSRF mode double-submit, "
    "yang boleh tanpa HttpOnly."
)
ADVICE_SAMESITE_MISSING = (
    "Tetapkan SameSite secara eksplisit (Lax untuk sebagian besar kasus, Strict untuk "
    "yang sensitif). Tanpa atribut, perilaku bergantung pada browser."
)
ADVICE_SAMESITE_NONE_INSECURE = (
    "SameSite=None wajib disertai Secure. Browser modern menolak cookie seperti ini, "
    "jadi cookie tidak pernah tersimpan. Tambahkan Secure, atau pakai Lax."
)
ADVICE_SAMESITE_NONE = (
    "SameSite=None membuat cookie ikut terkirim pada permintaan lintas situs, sehingga "
    "perlindungan CSRF harus datang dari mekanisme lain (token CSRF). Pakai Lax atau "
    "Strict kalau tidak benar-benar butuh lintas situs."
)
ADVICE_SAMESITE_INVALID = (
    "SameSite hanya boleh Strict, Lax, atau None. Nilai lain diabaikan browser dan "
    "diperlakukan seperti atribut yang tidak ada."
)
ADVICE_PREFIX_SECURE = (
    "Awalan __Secure- mewajibkan atribut Secure. Browser menolak cookie yang melanggarnya."
)
ADVICE_PREFIX_HOST = (
    "Awalan __Host- mewajibkan Secure, Path=/, dan tanpa Domain. Browser menolak cookie "
    "yang melanggarnya."
)


@dataclass(frozen=True)
class Cookie:
    name: str
    attributes: dict[str, str]  # nama atribut (huruf kecil) -> nilai atribut, bukan nilai cookie

    @property
    def secure(self) -> bool:
        return "secure" in self.attributes

    @property
    def http_only(self) -> bool:
        return "httponly" in self.attributes


@dataclass(frozen=True)
class CookieReport:
    findings: list[Finding]
    skipped: list[str]
    cookies_seen: int


def _clean(value: str) -> str:
    text = "".join(ch if ch.isprintable() else "?" for ch in value)
    return text if len(text) <= EVIDENCE_MAX else text[:EVIDENCE_MAX] + "..."


def parse_set_cookie(line: str) -> Cookie | None:
    """Urai satu header Set-Cookie. Nilai cookie dibuang. None kalau tidak bernama."""
    first, *rest = line.split(";")
    name, separator, _value = first.partition("=")
    name = name.strip()
    if not separator or not name:
        return None
    attributes: dict[str, str] = {}
    for part in rest:
        key, _, value = part.partition("=")
        key = key.strip().lower()
        if key:
            attributes[key] = value.strip()  # atribut ganda: yang terakhir berlaku
    return Cookie(name, attributes)


def classify(name: str) -> str:
    """'csrf', 'sensitif', atau 'biasa'. Hanya dari nama, jadi keyakinannya terbatas."""
    low = name.lower()
    if CSRF.search(low):
        return "csrf"
    if any(s in low for s in SENSITIVE_SUBSTRINGS) or SENSITIVE_WORDS.search(low):
        return "sensitif"
    return "biasa"


def _evidence(cookie: Cookie) -> str:
    parts = []
    for key in sorted(cookie.attributes):
        if key == "samesite":
            parts.append(f"SameSite={cookie.attributes[key] or '(kosong)'}")
        else:
            parts.append(KNOWN_ATTRIBUTES.get(key, key))
    shown = ", ".join(parts) if parts else "(tidak ada)"
    return _clean(f"cookie '{_clean(cookie.name)}': atribut {shown}")


def _check_cookie(cookie: Cookie, url: str, https: bool) -> list[Finding]:
    kind = classify(cookie.name)
    sensitive = kind == "sensitif"
    evidence = _evidence(cookie)
    low = cookie.name.lower()
    secure_prefix = low.startswith(("__host-", "__secure-"))
    findings: list[Finding] = []

    def add(id_: str, title: str, severity: str, confidence: str, advice: str) -> None:
        findings.append(Finding(id_, title, severity, confidence, url, evidence, advice))

    if low.startswith("__host-"):
        host_ok = (
            cookie.secure
            and cookie.attributes.get("path") == "/"
            and "domain" not in cookie.attributes
        )
        if not host_ok:
            add(
                "cookie-prefix-invalid",
                "Awalan nama cookie dilanggar (cookie ditolak browser)",
                "rendah", "tinggi", ADVICE_PREFIX_HOST,
            )  # fmt: skip
    elif low.startswith("__secure-") and not cookie.secure:
        add(
            "cookie-prefix-invalid",
            "Awalan nama cookie dilanggar (cookie ditolak browser)",
            "rendah", "tinggi", ADVICE_PREFIX_SECURE,
        )  # fmt: skip

    if https and not cookie.secure and not secure_prefix:
        add(
            "cookie-no-secure", "Cookie tanpa atribut Secure",
            "sedang" if sensitive else "rendah", "sedang", ADVICE_SECURE,
        )  # fmt: skip

    if not cookie.http_only and kind != "csrf":
        add(
            "cookie-no-httponly", "Cookie tanpa HttpOnly (terbaca oleh JavaScript)",
            "sedang" if sensitive else "rendah",
            "sedang" if sensitive else "rendah",
            ADVICE_HTTPONLY,
        )  # fmt: skip

    samesite = cookie.attributes.get("samesite")
    if samesite is None:
        add(
            "cookie-no-samesite", "Cookie tanpa atribut SameSite",
            "rendah", "sedang" if sensitive else "rendah", ADVICE_SAMESITE_MISSING,
        )  # fmt: skip
    elif samesite.lower() not in SAMESITE_VALUES:
        add(
            "cookie-samesite-invalid", "Nilai SameSite tidak sah",
            "rendah", "tinggi", ADVICE_SAMESITE_INVALID,
        )  # fmt: skip
    elif samesite.lower() == "none":
        if not cookie.secure:
            add(
                "cookie-samesite-none-insecure",
                "SameSite=None tanpa Secure (cookie ditolak browser modern)",
                "sedang", "tinggi", ADVICE_SAMESITE_NONE_INSECURE,
            )  # fmt: skip
        elif sensitive:
            add(
                "cookie-samesite-none",
                "Cookie sensitif dengan SameSite=None (dikirim lintas situs)",
                "rendah", "sedang", ADVICE_SAMESITE_NONE,
            )  # fmt: skip
    return findings


def check_cookies(response: Response) -> CookieReport:
    https = response.url.startswith("https://")
    lines = response.headers.get_list("set-cookie")
    cookies: list[Cookie] = []
    unreadable = 0
    for line in lines:
        cookie = parse_set_cookie(line)
        if cookie is None:
            unreadable += 1
        else:
            cookies.append(cookie)

    skipped = [SCOPE_NOTE]
    if not lines:
        skipped.append("tidak ada Set-Cookie pada respons ini, tidak ada yang dinilai")
    if response.history:
        skipped.append(
            f"cookie pada {len(response.history)} respons redirect sebelum tujuan akhir "
            "tidak diperiksa"
        )
    if unreadable:
        skipped.append(
            f"{unreadable} header Set-Cookie tidak bisa dibaca (tanpa nama=nilai) dan dilewati"
        )
    if lines and not https:
        skipped.append(
            "Secure tidak dinilai: respons lewat HTTP polos (browser modern menolak "
            "cookie Secure dari HTTP, jadi bagian ini hanya bermakna lewat HTTPS)"
        )

    findings: list[Finding] = []
    for cookie in cookies:
        findings += _check_cookie(cookie, response.url, https)
    return CookieReport(findings, skipped, len(cookies))
