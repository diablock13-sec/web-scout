"""Satu-satunya jalan keluar ke jaringan. Semua permintaan wajib lewat Fetcher.

Setiap URL, termasuk tujuan redirect, diperiksa pagar lingkup (scope.py). Setelah DNS,
alamat diverifikasi dan koneksi dibuat ke alamat itu, bukan ke hasil resolve ulang.
Modul lain tidak boleh mengimpor httpx sendiri (dijaga oleh test).
"""

import ssl
import time
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Self
from urllib.parse import urljoin, urlsplit

import httpx

from web_scout.scope import (
    DEFAULT_PORTS,
    Scope,
    ScopeError,
    Target,
    check_connectable,
    check_target,
    resolve_host,
)

USER_AGENT = "web-scout/0.1 (pemindai keamanan; hanya untuk target milik sendiri)"
MAX_REDIRECTS = 5
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
TIMEOUT = httpx.Timeout(10.0, connect=5.0)


class FetchError(RuntimeError):
    """Permintaan gagal atau tidak diikuti. Pesannya tidak memuat isi galat asli."""


@dataclass(frozen=True)
class Response:
    url: str
    status: int
    headers: httpx.Headers
    body: bytes = b""
    truncated: bool = False
    history: tuple[str, ...] = ()


def _bracket(host: str) -> str:
    return f"[{host}]" if ":" in host else host


def _host_header(target: Target) -> str:
    host = _bracket(target.host)
    return host if target.port == DEFAULT_PORTS[target.scheme] else f"{host}:{target.port}"


def _pinned_url(target: Target, address: str) -> str:
    parts = urlsplit(target.url)
    path = parts.path or "/"
    query = f"?{parts.query}" if parts.query else ""
    ip = _bracket(address.split("%", 1)[0])
    return f"{target.scheme}://{ip}:{target.port}{path}{query}"


def describe_error(error: BaseException) -> str:
    """Ringkas penyebab galat jaringan tanpa membocorkan pesan aslinya (yang bisa memuat
    URL, alamat internal, atau data lain)."""
    current: BaseException | None = error
    for _ in range(10):  # batas, supaya rantai sebab yang melingkar tidak menggantung
        if current is None:
            break
        if isinstance(current, ssl.SSLCertVerificationError):
            return "sertifikat TLS tidak valid"
        if isinstance(current, ssl.SSLError):
            return "kegagalan TLS"
        if isinstance(current, ConnectionRefusedError):
            return "koneksi ditolak (tidak ada yang mendengarkan di port itu)"
        if isinstance(current, ConnectionResetError):
            return "koneksi diputus oleh server"
        current = current.__cause__ or current.__context__
    return f"gagal terhubung ({type(error).__name__})"


class Fetcher:
    def __init__(
        self,
        scope: Scope | None = None,
        *,
        transport: httpx.BaseTransport | None = None,
        min_interval: float = 0.2,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
        resolver: Callable[[str], list[str]] = resolve_host,
    ):
        self.scope = scope or Scope()
        self.min_interval = min_interval
        self._sleep = sleep
        self._clock = clock
        self._resolver = resolver
        self._last: float | None = None
        self._client = httpx.Client(
            transport=transport,
            follow_redirects=False,  # redirect diikuti manual, tiap tujuan diperiksa ulang
            trust_env=False,  # abaikan HTTP_PROXY dan sejenisnya
            timeout=TIMEOUT,
        )

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def close(self) -> None:
        self._client.close()

    def get(self, raw_url: str, *, max_body: int = 0) -> Response:
        """GET dengan pagar lingkup. Target awal di luar lingkup melempar ScopeError;
        redirect ke luar lingkup melempar FetchError dan tidak diikuti."""
        history: list[str] = []
        url = raw_url
        for _ in range(MAX_REDIRECTS + 1):
            try:
                target = check_target(url, self.scope)
                addresses = check_connectable(target, self._resolver)
            except ScopeError as e:
                if not history:
                    raise
                raise FetchError(f"redirect ke luar lingkup tidak diikuti: {e}") from None
            response, location = self._send(target, addresses[0], max_body)
            if response.status not in REDIRECT_STATUSES or not location:
                return replace(response, history=tuple(history))
            history.append(target.url)
            url = urljoin(target.url, location)
        raise FetchError("terlalu banyak redirect")

    def _wait(self) -> None:
        if self._last is not None:
            remaining = self.min_interval - (self._clock() - self._last)
            if remaining > 0:
                self._sleep(remaining)
        self._last = self._clock()

    def _send(
        self, target: Target, address: str, max_body: int
    ) -> tuple[Response, str | None]:
        self._wait()
        extensions = {"sni_hostname": target.host} if target.scheme == "https" else {}
        headers = {
            "Host": _host_header(target),
            "User-Agent": USER_AGENT,
            "Accept": "*/*",
        }
        try:
            with self._client.stream(
                "GET", _pinned_url(target, address), headers=headers, extensions=extensions
            ) as r:
                body, truncated = self._read(r, max_body)
                response = Response(
                    url=target.url,
                    status=r.status_code,
                    headers=r.headers,
                    body=body,
                    truncated=truncated,
                )
                location = r.headers.get("location")
        except httpx.TimeoutException:
            raise FetchError("timeout") from None
        except httpx.HTTPError as e:
            raise FetchError(describe_error(e)) from None
        finally:
            self._client.cookies.clear()  # tidak ada sesi yang terbawa antar permintaan
        return response, location

    @staticmethod
    def _read(response: httpx.Response, max_body: int) -> tuple[bytes, bool]:
        if max_body <= 0:
            return b"", False
        body = bytearray()
        for chunk in response.iter_bytes():
            room = max_body - len(body)
            body += chunk[:room]
            if len(chunk) > room:
                return bytes(body), True
        return bytes(body), False
