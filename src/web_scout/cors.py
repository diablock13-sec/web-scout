"""Pemeriksa CORS. Mengirim beberapa GET dengan header Origin buatan lewat Fetcher (jadi
tetap di dalam pagar lingkup), lalu menilai Access-Control-Allow-Origin dan
Access-Control-Allow-Credentials pada tiap respons.

Batas: hanya permintaan GET sederhana. Preflight (OPTIONS) tidak diuji.
"""

import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass

from web_scout.client import Fetcher, Response
from web_scout.headers import EVIDENCE_MAX, Finding
from web_scout.scope import parse_target

FOREIGN_ORIGIN = "https://evil.example"
NULL_ORIGIN = "null"
NOT_TESTED = "preflight (OPTIONS) tidak diuji: hanya permintaan GET sederhana"

ADVICE_REFLECT_CREDS = (
    "Server memantulkan Origin apa pun dan mengizinkan credentials: situs mana pun bisa "
    "membaca respons pengguna yang sedang login. Pakai daftar putih origin yang eksplisit "
    "(bandingkan persis, bukan dengan regex longgar), dan jangan kirim "
    "Access-Control-Allow-Credentials untuk origin di luar daftar."
)
ADVICE_REFLECT = (
    "Server memantulkan Origin apa pun, setara dengan wildcard dan sering jadi awal "
    "kelemahan yang lebih parah. Pakai daftar putih origin yang eksplisit."
)
ADVICE_NULL_CREDS = (
    "Origin 'null' diizinkan dengan credentials. Iframe bersandbox dan file lokal "
    "mengirim Origin null, jadi penyerang bisa membaca respons pengguna. Jangan pernah "
    "mengizinkan 'null'."
)
ADVICE_NULL = (
    "Origin 'null' diizinkan. Iframe bersandbox dan file lokal mengirim Origin null. "
    "Jangan mengizinkan 'null'."
)
ADVICE_LOOKALIKE_CREDS = (
    "Origin yang hanya mirip nama host target diterima dan credentials diizinkan. "
    "Validasi origin kemungkinan memakai pencocokan sebagian (awalan, akhiran, atau regex "
    "longgar). Bandingkan seluruh origin secara persis dengan daftar putih."
)
ADVICE_LOOKALIKE = (
    "Origin yang hanya mirip nama host target diterima. Validasi origin kemungkinan "
    "memakai pencocokan sebagian. Bandingkan seluruh origin secara persis."
)
ADVICE_WILDCARD_CREDS = (
    "Access-Control-Allow-Origin: * bersama Access-Control-Allow-Credentials: true ditolak "
    "browser, jadi tidak langsung bisa dieksploitasi, tapi menandakan konfigurasi yang "
    "salah arah. Putuskan origin mana yang boleh dan sebut secara eksplisit."
)
ADVICE_WILDCARD = (
    "Wildcard wajar untuk konten publik tanpa login. Hindari kalau respons memuat data "
    "yang hanya boleh dilihat dari jaringan tertentu (intranet) atau bergantung pada "
    "alamat IP. Sebut origin yang diizinkan kalau ragu."
)
ADVICE_VARY = (
    "Respons memantulkan Origin tetapi tidak mencantumkan Vary: Origin, sehingga cache "
    "bersama bisa menyajikan respons satu origin ke origin lain. Tambahkan Vary: Origin."
)

# label -> (id, judul, saran tanpa credentials, saran dengan credentials)
REFLECTION = {
    "asing": ("cors-reflect", "CORS memantulkan origin sembarang", ADVICE_REFLECT, ADVICE_REFLECT_CREDS),
    "null": ("cors-null", "CORS mengizinkan origin 'null'", ADVICE_NULL, ADVICE_NULL_CREDS),
    "mirip": (
        "cors-lookalike",
        "CORS menerima origin yang hanya mirip nama host",
        ADVICE_LOOKALIKE,
        ADVICE_LOOKALIKE_CREDS,
    ),
}


@dataclass(frozen=True)
class ProbeResult:
    label: str  # baseline | asing | null | mirip
    origin: str | None  # None: permintaan tanpa header Origin
    response: Response


@dataclass(frozen=True)
class CorsReport:
    findings: list[Finding]
    skipped: list[str]
    results: list[ProbeResult]


def _clean(value: str) -> str:
    text = "".join(ch if ch.isprintable() else "?" for ch in value)
    return text if len(text) <= EVIDENCE_MAX else text[:EVIDENCE_MAX] + "..."


def _acao(result: ProbeResult) -> str | None:
    value = result.response.headers.get("access-control-allow-origin")
    return None if value is None else value.strip()


def _credentials(result: ProbeResult) -> bool:
    # Spesifikasi: hanya nilai persis "true" (huruf kecil) yang berarti credentials diizinkan.
    return result.response.headers.get("access-control-allow-credentials", "").strip() == "true"


def _varies_on_origin(response: Response) -> bool:
    tokens = {
        token.strip().lower()
        for value in response.headers.get_list("vary")
        for token in value.split(",")
    }
    return "origin" in tokens or "*" in tokens


def _evidence(result: ProbeResult) -> str:
    headers = result.response.headers
    origin = result.origin if result.origin is not None else "(tanpa Origin)"
    acao = headers.get("access-control-allow-origin", "(tidak ada)")
    acac = headers.get("access-control-allow-credentials", "(tidak ada)")
    return _clean(
        f"Origin: {origin} -> Access-Control-Allow-Origin: {acao}; "
        f"Access-Control-Allow-Credentials: {acac}"
    )


def check_cors(results: list[ProbeResult], extra_skipped: Iterable[str] = ()) -> CorsReport:
    skipped = [NOT_TESTED, *extra_skipped]
    if not any(_acao(r) is not None for r in results):
        skipped.append("tidak ada header CORS pada respons mana pun, tidak ada yang dinilai")
        return CorsReport([], skipped, list(results))

    findings: list[Finding] = []
    reflected = {
        r.label: r
        for r in results
        if r.label in REFLECTION and r.origin is not None and _acao(r) == r.origin
    }
    if "asing" in reflected:
        reflected.pop("mirip", None)  # origin sembarang yang dipantulkan sudah mencakupnya

    for label, r in reflected.items():
        id_, title, plain, with_creds = REFLECTION[label]
        url = r.response.url
        if _credentials(r):
            findings.append(
                Finding(
                    f"{id_}-credentials", f"{title} dan mengizinkan credentials",
                    "tinggi", "tinggi", url, _evidence(r), with_creds,
                )
            )  # fmt: skip
        else:
            findings.append(Finding(id_, title, "sedang", "sedang", url, _evidence(r), plain))

    wildcard = next((r for r in results if _acao(r) == "*"), None)
    if wildcard is not None:
        url = wildcard.response.url
        if _credentials(wildcard):
            findings.append(
                Finding(
                    "cors-wildcard-credentials", "CORS memakai wildcard bersama credentials",
                    "sedang", "tinggi", url, _evidence(wildcard), ADVICE_WILDCARD_CREDS,
                )
            )  # fmt: skip
        else:
            findings.append(
                Finding(
                    "cors-wildcard", "CORS mengizinkan semua origin (*)",
                    "rendah", "sedang", url, _evidence(wildcard), ADVICE_WILDCARD,
                )
            )  # fmt: skip

    no_vary = next((r for r in reflected.values() if not _varies_on_origin(r.response)), None)
    if no_vary is not None:
        vary = no_vary.response.headers.get("vary", "(tidak ada)")
        findings.append(
            Finding(
                "cors-vary-missing", "Respons CORS yang memantulkan Origin tanpa Vary: Origin",
                "rendah", "sedang", no_vary.response.url, _clean(f"Vary: {vary}"), ADVICE_VARY,
            )
        )  # fmt: skip
    return CorsReport(findings, skipped, list(results))


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def run_probes(fetcher: Fetcher, url: str) -> CorsReport:
    """Kirim permintaan uji lewat fetcher (yang menjaga lingkup) lalu nilai hasilnya."""
    host = parse_target(url).host
    plan: list[tuple[str, str | None]] = [
        ("baseline", None),
        ("asing", FOREIGN_ORIGIN),
        ("null", NULL_ORIGIN),
    ]
    extra_skipped = []
    if _is_ip(host):
        extra_skipped.append("uji origin mirip dilewati: host berupa alamat IP")
    else:
        plan.append(("mirip", f"https://{host}.evil.example"))

    results = []
    for label, origin in plan:
        response = fetcher.get(url, headers={"Origin": origin} if origin else None)
        results.append(ProbeResult(label, origin, response))
    return check_cors(results, extra_skipped)
