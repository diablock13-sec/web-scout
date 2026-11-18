"""Antarmuka baris perintah web-scout. Semua akses jaringan lewat Fetcher (pagar lingkup)."""

import argparse
import json
import sys
from collections.abc import Callable
from dataclasses import asdict
from importlib import metadata

from web_scout.client import Fetcher, FetchError, Response
from web_scout.cookies import CookieReport, check_cookies
from web_scout.cors import CorsReport, run_probes
from web_scout.headers import Finding, HeaderReport, check_headers
from web_scout.scope import Scope, ScopeError, build_scope

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2
SEVERITY_ORDER = {"tinggi": 0, "sedang": 1, "rendah": 2}
SHOWN_MAX = 100

FetcherFactory = Callable[[Scope], Fetcher]


def _safe(value: str) -> str:
    """Teks dari server dicetak tanpa karakter kendali dan dengan panjang terbatas."""
    text = "".join(ch if ch.isprintable() else "?" for ch in value)
    return text if len(text) <= SHOWN_MAX else text[:SHOWN_MAX] + "..."


def _finding_lines(findings: list[Finding], none_message: str) -> list[str]:
    if not findings:
        return ["", none_message]
    ordered = sorted(findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.id))
    lines = ["", f"{len(ordered)} temuan:"]
    for f in ordered:
        lines += [
            "",
            f"[{f.severity.upper()}] {f.title}  (keyakinan: {f.confidence})",
            f"  bukti : {f.evidence}",
            f"  saran : {f.advice}",
        ]
    return lines


def _skipped_lines(skipped: list[str]) -> list[str]:
    if not skipped:
        return []
    return ["", "Tidak diperiksa:", *[f"  - {reason}" for reason in skipped]]


def format_text(response: Response, report: HeaderReport) -> str:
    lines = [f"Target  : {response.url}  (status {response.status})"]
    if response.history:
        hops = [*response.history, response.url]
        lines.append("Redirect: " + " -> ".join(hops))
    lines += _finding_lines(report.findings, "Tidak ada temuan pada header yang diperiksa.")
    lines += _skipped_lines(report.skipped)
    lines += [
        "",
        "Catatan: laporan ini hanya menilai header respons, bukan keamanan aplikasi.",
    ]
    return "\n".join(lines)


def format_json(response: Response, report: HeaderReport) -> str:
    return json.dumps(
        {
            "url": response.url,
            "status": response.status,
            "redirects": list(response.history),
            "findings": [asdict(f) for f in report.findings],
            "skipped": report.skipped,
        },
        ensure_ascii=False,
        indent=2,
    )


def format_cors_text(report: CorsReport) -> str:
    lines = [f"Target  : {report.results[0].response.url}", "", "Permintaan uji:"]
    for r in report.results:
        shown = f"Origin: {_safe(r.origin)}" if r.origin is not None else "tanpa Origin"
        acao = _safe(r.response.headers.get("access-control-allow-origin", "(tidak ada)"))
        lines.append(f"  {r.label:<9} {shown:<34} -> {r.response.status}  ACAO: {acao}")
    lines += _finding_lines(report.findings, "Tidak ada temuan CORS pada permintaan yang diuji.")
    lines += _skipped_lines(report.skipped)
    lines += ["", "Catatan: hanya GET sederhana yang diuji, bukan seluruh perilaku CORS."]
    return "\n".join(lines)


def format_cors_json(report: CorsReport) -> str:
    return json.dumps(
        {
            "url": report.results[0].response.url,
            "requests": [
                {
                    "label": r.label,
                    "origin": r.origin,
                    "status": r.response.status,
                    "access_control_allow_origin": r.response.headers.get(
                        "access-control-allow-origin"
                    ),
                }
                for r in report.results
            ],
            "findings": [asdict(f) for f in report.findings],
            "skipped": report.skipped,
        },
        ensure_ascii=False,
        indent=2,
    )


def format_cookies_text(response: Response, report: CookieReport) -> str:
    lines = [
        f"Target  : {response.url}  (status {response.status})",
        f"Cookie  : {report.cookies_seen} header Set-Cookie dibaca",
    ]
    if response.history:
        lines.append("Redirect: " + " -> ".join([*response.history, response.url]))
    lines += _finding_lines(report.findings, "Tidak ada temuan pada cookie yang diperiksa.")
    lines += _skipped_lines(report.skipped)
    lines += ["", "Catatan: nilai cookie tidak pernah ditampilkan, hanya nama dan atribut."]
    return "\n".join(lines)


def format_cookies_json(response: Response, report: CookieReport) -> str:
    return json.dumps(
        {
            "url": response.url,
            "status": response.status,
            "redirects": list(response.history),
            "cookies_seen": report.cookies_seen,
            "findings": [asdict(f) for f in report.findings],
            "skipped": report.skipped,
        },
        ensure_ascii=False,
        indent=2,
    )


def cmd_headers(
    url: str,
    *,
    allow: list[str],
    i_own_this: bool,
    as_json: bool,
    make_fetcher: FetcherFactory,
) -> int:
    try:
        scope = build_scope(allow, i_own_this=i_own_this)
        with make_fetcher(scope) as fetcher:
            response = fetcher.get(url)
    except (ScopeError, FetchError) as e:
        print(f"web-scout: {e}", file=sys.stderr)
        return EXIT_ERROR

    report = check_headers(response)
    print(format_json(response, report) if as_json else format_text(response, report))
    return EXIT_FINDINGS if report.findings else EXIT_OK


def cmd_cors(
    url: str,
    *,
    allow: list[str],
    i_own_this: bool,
    as_json: bool,
    make_fetcher: FetcherFactory,
) -> int:
    try:
        scope = build_scope(allow, i_own_this=i_own_this)
        with make_fetcher(scope) as fetcher:
            report = run_probes(fetcher, url)
    except (ScopeError, FetchError) as e:
        print(f"web-scout: {e}", file=sys.stderr)
        return EXIT_ERROR

    print(format_cors_json(report) if as_json else format_cors_text(report))
    return EXIT_FINDINGS if report.findings else EXIT_OK


def cmd_cookies(
    url: str,
    *,
    allow: list[str],
    i_own_this: bool,
    as_json: bool,
    make_fetcher: FetcherFactory,
) -> int:
    try:
        scope = build_scope(allow, i_own_this=i_own_this)
        with make_fetcher(scope) as fetcher:
            response = fetcher.get(url)
    except (ScopeError, FetchError) as e:
        print(f"web-scout: {e}", file=sys.stderr)
        return EXIT_ERROR

    report = check_cookies(response)
    print(
        format_cookies_json(response, report)
        if as_json
        else format_cookies_text(response, report)
    )
    return EXIT_FINDINGS if report.findings else EXIT_OK


def _target_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("url", help="contoh: http://127.0.0.1:3000/")
    parser.add_argument(
        "--allow",
        action="append",
        metavar="HOST",
        help="izinkan host selain loopback (ulangi untuk beberapa), wajib dengan --i-own-this",
    )
    parser.add_argument(
        "--i-own-this",
        action="store_true",
        help="konfirmasi bahwa kamu pemilik target atau punya izin tertulis",
    )
    parser.add_argument("--json", action="store_true", help="keluaran JSON")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="web-scout",
        description="Pemindai keamanan dasar untuk target milik sendiri.",
        epilog="Kode keluar: 0 tidak ada temuan, 1 ada temuan, 2 galat.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {metadata.version('web-scout')}",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    _target_options(sub.add_parser("headers", help="periksa header keamanan sebuah URL"))
    _target_options(
        sub.add_parser("cors", help="periksa konfigurasi CORS (mengirim 4 permintaan GET)")
    )
    _target_options(
        sub.add_parser("cookies", help="periksa flag cookie (Secure, HttpOnly, SameSite)")
    )
    return parser


def main(argv: list[str] | None = None, *, make_fetcher: FetcherFactory = Fetcher) -> int:
    args = build_parser().parse_args(argv)
    run = {"headers": cmd_headers, "cors": cmd_cors, "cookies": cmd_cookies}[args.command]
    return run(
        args.url,
        allow=args.allow or [],
        i_own_this=args.i_own_this,
        as_json=args.json,
        make_fetcher=make_fetcher,
    )
