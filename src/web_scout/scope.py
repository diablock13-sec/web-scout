"""Pagar lingkup: host mana yang boleh disentuh scanner.

Bawaan: hanya loopback (127.0.0.0/8, ::1, 'localhost'). Host lain harus diizinkan
eksplisit dengan --allow HOST dan dikonfirmasi dengan --i-own-this. Tanpa wildcard.
Semua pemeriksaan gagal tertutup: yang tidak bisa dibuktikan masuk lingkup, ditolak.

Kontrak untuk pemanggil:
- Periksa SETIAP URL yang akan diakses dengan check_target, termasuk tujuan redirect.
- Panggil check_connectable (atau verify_resolved) setelah DNS dan sebelum connect,
  lalu connect ke alamat yang dikembalikan, jangan resolve ulang.
"""

import ipaddress
import re
import socket
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

PRINTABLE_MIN = 33  # '!'
PRINTABLE_MAX = 126  # '~'
DEFAULT_PORTS = {"http": 80, "https": 443}
LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
HOST_RE = re.compile(rf"^(?=.{{1,253}}$){LABEL}(?:\.{LABEL})*$")
ALLOW_FORBIDDEN = "/:@?#\\[]%"


class ScopeError(ValueError):
    """Target atau konfigurasi lingkup ditolak."""


@dataclass(frozen=True)
class Target:
    url: str  # sudah dinormalisasi, tanpa fragmen
    scheme: str
    host: str
    port: int
    loopback: bool


@dataclass(frozen=True)
class Scope:
    """Host yang diizinkan selain loopback. Bangun lewat build_scope."""

    allowed: frozenset[str] = frozenset()


def _ascii_printable(text: str) -> bool:
    return all(PRINTABLE_MIN <= ord(ch) <= PRINTABLE_MAX for ch in text)


def _as_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def _ip_is_loopback(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if ip.is_loopback:
        return True
    mapped = getattr(ip, "ipv4_mapped", None)
    return bool(mapped and mapped.is_loopback)


def is_loopback_host(host: str) -> bool:
    if host == "localhost":
        return True
    ip = _as_ip(host)
    return ip is not None and _ip_is_loopback(ip)


def parse_target(raw: str) -> Target:
    """Urai URL dengan ketat. Tidak menebak skema, tidak memaafkan bentuk ganjil."""
    if not isinstance(raw, str) or not raw:
        raise ScopeError("URL kosong")
    if not _ascii_printable(raw):
        raise ScopeError(
            "URL hanya boleh berisi karakter ASCII yang tercetak, "
            "tanpa spasi, karakter kendali, atau huruf non-ASCII"
        )
    if "\\" in raw:
        raise ScopeError("URL tidak boleh memuat garis miring terbalik")
    try:
        parts = urlsplit(raw)
        port = parts.port
    except ValueError:
        raise ScopeError("URL tidak bisa dibaca (alamat atau port tidak sah)") from None
    if parts.scheme not in DEFAULT_PORTS:
        raise ScopeError("skema harus http atau https, ditulis lengkap (http://...)")
    if "@" in parts.netloc:
        raise ScopeError("URL tidak boleh berisi kredensial atau '@'")
    if port == 0:
        raise ScopeError("port 0 tidak sah")

    host = parts.hostname or ""
    host = host.removesuffix(".")
    if not host:
        raise ScopeError("URL tidak punya host (contoh: http://127.0.0.1:3000)")
    ip = _as_ip(host)
    if ip is not None:
        host = str(ip)
    elif not HOST_RE.match(host):
        raise ScopeError(f"host tidak sah: {host!r}")

    shown = f"[{host}]" if ":" in host else host
    netloc = shown if port is None else f"{shown}:{port}"
    url = urlunsplit((parts.scheme, netloc, parts.path or "/", parts.query, ""))
    return Target(
        url=url,
        scheme=parts.scheme,
        host=host,
        port=port or DEFAULT_PORTS[parts.scheme],
        loopback=is_loopback_host(host),
    )


def _normalize_allow(entry: str) -> str:
    if not isinstance(entry, str) or not entry:
        raise ScopeError("entri --allow kosong")
    if "*" in entry:
        raise ScopeError(f"wildcard tidak diizinkan: {entry!r}")
    if not _ascii_printable(entry):
        raise ScopeError(f"entri --allow berisi karakter tidak sah: {entry!r}")
    ip = _as_ip(entry)
    if ip is not None:
        if ip.is_unspecified:
            raise ScopeError(f"alamat {entry} tidak boleh dipakai sebagai target")
        return str(ip)
    if any(ch in entry for ch in ALLOW_FORBIDDEN):
        raise ScopeError(
            f"{entry!r}: tulis hanya nama host atau alamat IP, "
            "tanpa skema, port, path, atau rentang (CIDR)"
        )
    host = entry.lower()
    if not HOST_RE.match(host):
        raise ScopeError(f"nama host tidak sah: {entry!r}")
    if "." not in host and host != "localhost":
        raise ScopeError(
            f"{entry!r}: nama satu kata terlalu luas, tulis nama lengkap atau alamat IP"
        )
    return host


def build_scope(allow: Iterable[str] = (), *, i_own_this: bool = False) -> Scope:
    entries = [_normalize_allow(e) for e in allow]
    if entries and not i_own_this:
        raise ScopeError(
            "--allow membutuhkan --i-own-this "
            "(konfirmasi bahwa kamu pemilik target atau punya izin tertulis)"
        )
    if i_own_this and not entries:
        raise ScopeError("--i-own-this tanpa --allow tidak berarti apa-apa")
    return Scope(frozenset(entries))


def check_target(raw: str, scope: Scope | None = None) -> Target:
    """Kembalikan Target kalau masuk lingkup, kalau tidak lempar ScopeError."""
    scope = scope or Scope()
    target = parse_target(raw)
    if target.loopback or target.host in scope.allowed:
        return target
    raise ScopeError(
        f"{target.host} di luar lingkup. Bawaan hanya loopback; kalau ini milikmu, "
        f"tambahkan --allow {target.host} dan --i-own-this"
    )


def _address_is_loopback(address: str) -> bool:
    ip = _as_ip(address.split("%", 1)[0])
    return ip is not None and _ip_is_loopback(ip)


def verify_resolved(target: Target, addresses: Iterable[str]) -> None:
    """Dipanggil setelah DNS, sebelum connect. Target loopback hanya boleh menuju
    alamat loopback (menahan 'localhost' yang dibelokkan lewat hosts atau DNS)."""
    resolved = list(addresses)
    if not resolved:
        raise ScopeError(f"{target.host} tidak bisa di-resolve")
    if target.loopback:
        bad = [a for a in resolved if not _address_is_loopback(a)]
        if bad:
            raise ScopeError(
                f"{target.host} menuju alamat non-loopback ({bad[0]}), "
                "kemungkinan DNS atau file hosts dibelokkan"
            )


def resolve_host(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise ScopeError(f"{host} tidak bisa di-resolve") from None
    return sorted({str(info[4][0]) for info in infos})


def check_connectable(
    target: Target, resolver: Callable[[str], list[str]] = resolve_host
) -> list[str]:
    """Resolve dan verifikasi. Hasilnya alamat yang harus dipakai untuk connect."""
    addresses = [target.host] if _as_ip(target.host) else resolver(target.host)
    verify_resolved(target, addresses)
    return addresses
