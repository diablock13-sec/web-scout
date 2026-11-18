"""Antarmuka baris perintah web-scout. Akses HTTP lewat Fetcher; pemindai port lewat
check_target dan check_connectable (hanya loopback)."""

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
from web_scout.ports import (
    DEFAULT_CONCURRENCY,
    DEFAULT_PORTS,
    DEFAULT_TIMEOUT,
    MAX_CONCURRENCY,
    PortReport,
    PortSpecError,
    parse_ports,
    run_scan,
)
from web_scout.scope import (
    Scope,
    ScopeError,
    build_scope,
    check_connectable,
    check_target,
)

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


def format_ports_text(report: PortReport) -> str:
    states = [r.state for r in report.results]
    summary = ", ".join(f"{states.count(s)} {s}" for s in ("open", "closed", "filtered", "error"))
    lines = [
        f"Target  : {_safe(report.host)}  (alamat {_safe(report.address)})",
        f"Dipindai: {len(report.results)} port ({summary})",
    ]
    opened = [r for r in report.results if r.state == "open"]
    if opened:
        lines += ["", "Port terbuka:"]
        for r in opened:
            banner = f"  {_safe(r.banner)}" if r.banner else ""
            lines.append(f"  {r.port:>5}/tcp{banner}")
    else:
        lines += ["", "Tidak ada port terbuka pada port yang dipindai."]
    if "error" in states:
        lines += ["", f"{states.count('error')} port gagal diperiksa (galat jaringan, detail tidak ditampilkan)."]
    lines += _skipped_lines(report.skipped)
    lines += ["", "Catatan: port terbuka adalah informasi, bukan temuan; kode keluar 0 kecuali galat."]
    return "\n".join(lines)


def format_ports_json(report: PortReport) -> str:
    return json.dumps(asdict(report), indent=2)


def cmd_ports(
    url: str,
    *,
    ports: str | None,
    concurrency: int,
    timeout: float,
    as_json: bool,
) -> int:
    try:
        target = check_target(url)  # lingkup bawaan: hanya loopback
        port_list = parse_ports(ports) if ports else sorted({*DEFAULT_PORTS, target.port})
        addresses = check_connectable(target)
    except (ScopeError, PortSpecError) as e:
        print(f"web-scout: {e}", file=sys.stderr)
        return EXIT_ERROR

    report = run_scan(
        target.host, addresses[0], port_list, concurrency=concurrency, timeout=timeout
    )
    if len(addresses) > 1:
        report.skipped.append(
            f"{target.host} punya {len(addresses)} alamat; hanya {addresses[0]} yang dipindai"
        )
    print(format_ports_json(report) if as_json else format_ports_text(report))
    return EXIT_OK


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
    ports_parser = sub.add_parser(
        "ports",
        help="pindai port TCP (hanya loopback); port terbuka bukan temuan, kode keluar 0 kecuali galat",
    )
    ports_parser.add_argument(
        "url", help="contoh: http://127.0.0.1:3000/ (port dalam URL ikut dipindai)"
    )
    ports_parser.add_argument(
        "--ports",
        metavar="DAFTAR",
        help="contoh: 80,443,8000-8010 (bawaan: 21 port umum ditambah port dalam URL)",
    )
    ports_parser.add_argument(
        "--concurrency",
        type=int,
        default=DEFAULT_CONCURRENCY,
        help=f"koneksi bersamaan (bawaan {DEFAULT_CONCURRENCY}, maksimum {MAX_CONCURRENCY})",
    )
    ports_parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"detik per koneksi (bawaan {DEFAULT_TIMEOUT})",
    )
    ports_parser.add_argument("--json", action="store_true", help="keluaran JSON")
    return parser


def main(argv: list[str] | None = None, *, make_fetcher: FetcherFactory = Fetcher) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "ports":
        return cmd_ports(
            args.url,
            ports=args.ports,
            concurrency=args.concurrency,
            timeout=args.timeout,
            as_json=args.json,
        )
    run = {"headers": cmd_headers, "cors": cmd_cors, "cookies": cmd_cookies}[args.command]
    return run(
        args.url,
        allow=args.allow or [],
        i_own_this=args.i_own_this,
        as_json=args.json,
        make_fetcher=make_fetcher,
    )
