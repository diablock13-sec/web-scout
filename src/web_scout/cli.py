"""Antarmuka baris perintah web-scout. Semua akses jaringan lewat Fetcher (pagar lingkup)."""

import argparse
import json
import sys
from collections.abc import Callable
from dataclasses import asdict
from importlib import metadata

from web_scout.client import Fetcher, FetchError, Response
from web_scout.headers import HeaderReport, check_headers
from web_scout.scope import Scope, ScopeError, build_scope

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2
SEVERITY_ORDER = {"tinggi": 0, "sedang": 1, "rendah": 2}

FetcherFactory = Callable[[Scope], Fetcher]


def format_text(response: Response, report: HeaderReport) -> str:
    lines = [f"Target  : {response.url}  (status {response.status})"]
    if response.history:
        hops = [*response.history, response.url]
        lines.append("Redirect: " + " -> ".join(hops))
    if report.findings:
        ordered = sorted(report.findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.id))
        lines += ["", f"{len(ordered)} temuan:"]
        for f in ordered:
            lines += [
                "",
                f"[{f.severity.upper()}] {f.title}  (keyakinan: {f.confidence})",
                f"  bukti : {f.evidence}",
                f"  saran : {f.advice}",
            ]
    else:
        lines += ["", "Tidak ada temuan pada header yang diperiksa."]
    if report.skipped:
        lines += ["", "Tidak diperiksa:"]
        lines += [f"  - {reason}" for reason in report.skipped]
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

    headers = sub.add_parser("headers", help="periksa header keamanan sebuah URL")
    headers.add_argument("url", help="contoh: http://127.0.0.1:3000/")
    headers.add_argument(
        "--allow",
        action="append",
        metavar="HOST",
        help="izinkan host selain loopback (ulangi untuk beberapa), wajib dengan --i-own-this",
    )
    headers.add_argument(
        "--i-own-this",
        action="store_true",
        help="konfirmasi bahwa kamu pemilik target atau punya izin tertulis",
    )
    headers.add_argument("--json", action="store_true", help="keluaran JSON")
    return parser


def main(argv: list[str] | None = None, *, make_fetcher: FetcherFactory = Fetcher) -> int:
    args = build_parser().parse_args(argv)
    return cmd_headers(
        args.url,
        allow=args.allow or [],
        i_own_this=args.i_own_this,
        as_json=args.json,
        make_fetcher=make_fetcher,
    )
