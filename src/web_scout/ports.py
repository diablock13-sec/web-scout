"""Pemindai port TCP connect. Tidak mengirim data apa pun; hanya membaca banner.

Modul ini tidak memeriksa lingkup. Pemanggil wajib memberi alamat yang sudah
diverifikasi oleh scope.py.
"""

import asyncio
from collections.abc import Iterable
from dataclasses import dataclass, field

DEFAULT_PORTS = (
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995,
    3000, 3306, 5432, 6379, 8000, 8080, 8443, 9200, 27017,
)
DEFAULT_CONCURRENCY = 100
MAX_CONCURRENCY = 500
DEFAULT_TIMEOUT = 1.0
MIN_TIMEOUT = 0.1
MAX_TIMEOUT = 10.0
BANNER_BYTES = 128
BANNER_WAIT = 0.5
BANNER_SHOWN_MAX = 100
SPEC_MAX_LEN = 200
BATCH = 1000

SKIPPED = (
    "hanya TCP connect: UDP, deteksi versi, dan SYN scan tidak ada",
    "closed dan filtered bisa dikacaukan firewall; filtered berarti tidak ada jawaban sebelum batas waktu",
    "banner hanya dibaca, tidak ada yang dikirim: layanan yang menunggu klien bicara dulu (misalnya HTTP) tampil tanpa banner",
)


class PortSpecError(ValueError):
    """Daftar port tidak valid."""


@dataclass(frozen=True)
class PortResult:
    port: int
    state: str  # "open", "closed", "filtered", atau "error"
    banner: str | None = None


@dataclass(frozen=True)
class PortReport:
    host: str
    address: str
    results: list[PortResult]
    skipped: list[str] = field(default_factory=list)


def _number(text: str) -> int:
    if not (text.isascii() and text.isdigit()):
        raise PortSpecError(f"bagian tidak valid: {text[:20]!r}")
    value = int(text)
    if not 1 <= value <= 65535:
        raise PortSpecError(f"port di luar 1-65535: {value}")
    return value


def parse_ports(spec: str) -> list[int]:
    """'80,443,8000-8010' menjadi daftar terurut tanpa duplikat."""
    if not spec or len(spec) > SPEC_MAX_LEN:
        raise PortSpecError("daftar port kosong atau terlalu panjang")
    found: set[int] = set()
    for part in spec.split(","):
        low, dash, high = part.strip().partition("-")
        start = _number(low)
        end = _number(high) if dash else start
        if end < start:
            raise PortSpecError(f"rentang terbalik: {part.strip()[:20]!r}")
        found.update(range(start, end + 1))
    return sorted(found)


def clamp_concurrency(value: int) -> int:
    return max(1, min(int(value), MAX_CONCURRENCY))


def clamp_timeout(value: float) -> float:
    return min(max(float(value), MIN_TIMEOUT), MAX_TIMEOUT)


def clean_banner(data: bytes) -> str:
    """Banner dari server adalah data tak tepercaya: tanpa karakter kendali, panjang terbatas."""
    text = data.decode("utf-8", errors="replace").strip()
    text = "".join(ch if ch.isprintable() else "?" for ch in text)
    return text if len(text) <= BANNER_SHOWN_MAX else text[:BANNER_SHOWN_MAX] + "..."


async def _probe(
    address: str,
    port: int,
    *,
    timeout: float,
    banner_wait: float,
    sem: asyncio.Semaphore,
) -> PortResult:
    async with sem:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(address, port), timeout
            )
        except ConnectionRefusedError:
            return PortResult(port, "closed")
        except TimeoutError:
            return PortResult(port, "filtered")
        except OSError:
            return PortResult(port, "error")

        banner = None
        try:
            data = await asyncio.wait_for(reader.read(BANNER_BYTES), banner_wait)
            banner = clean_banner(data) or None
        except (TimeoutError, OSError):
            pass
        finally:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), 1.0)
            except (TimeoutError, OSError):
                pass
        return PortResult(port, "open", banner)


async def scan_ports(
    address: str,
    ports: Iterable[int],
    *,
    concurrency: int = DEFAULT_CONCURRENCY,
    timeout: float = DEFAULT_TIMEOUT,
    banner_wait: float = BANNER_WAIT,
) -> list[PortResult]:
    unique = sorted(set(ports))
    if any(not 1 <= p <= 65535 for p in unique):
        raise PortSpecError("port di luar 1-65535")
    sem = asyncio.Semaphore(clamp_concurrency(concurrency))
    probe_timeout = clamp_timeout(timeout)
    wait = clamp_timeout(banner_wait)
    results: list[PortResult] = []
    for start in range(0, len(unique), BATCH):
        chunk = unique[start : start + BATCH]
        results += await asyncio.gather(
            *(
                _probe(address, p, timeout=probe_timeout, banner_wait=wait, sem=sem)
                for p in chunk
            )
        )
    return sorted(results, key=lambda r: r.port)


def run_scan(
    host: str,
    address: str,
    ports: Iterable[int],
    *,
    concurrency: int = DEFAULT_CONCURRENCY,
    timeout: float = DEFAULT_TIMEOUT,
    banner_wait: float = BANNER_WAIT,
) -> PortReport:
    results = asyncio.run(
        scan_ports(
            address,
            ports,
            concurrency=concurrency,
            timeout=timeout,
            banner_wait=banner_wait,
        )
    )
    return PortReport(host=host, address=address, results=results, skipped=list(SKIPPED))
