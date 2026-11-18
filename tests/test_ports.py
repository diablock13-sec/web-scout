import asyncio
import socket

import pytest

from web_scout import ports


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def scan(port_list, **options):
    return asyncio.run(ports.scan_ports("127.0.0.1", port_list, **options))


@pytest.mark.parametrize(
    ("spec", "expected"),
    [
        ("80", [80]),
        ("443,80,80", [80, 443]),
        ("1-3", [1, 2, 3]),
        ("80,8000-8002", [80, 8000, 8001, 8002]),
        (" 22 , 80 ", [22, 80]),
    ],
)
def test_parse_ports_valid(spec, expected):
    assert ports.parse_ports(spec) == expected


@pytest.mark.parametrize(
    "spec",
    [
        "", "0", "65536", "-1", "abc", "80,,443", "3-1", "1-2-3", "80-",
        "8 0", "1e3", "+80", "0x50", "٨٠", "１２", "x" * 201,
    ],
)
def test_parse_ports_invalid(spec):
    with pytest.raises(ports.PortSpecError):
        ports.parse_ports(spec)


def test_parse_ports_full_range():
    assert len(ports.parse_ports("1-65535")) == 65535


def test_clean_banner_replaces_controls():
    assert ports.clean_banner(b"\x1b[31mhalo\x00\r\n") == "?[31mhalo?"


def test_clean_banner_handles_invalid_utf8():
    assert "abc" in ports.clean_banner(b"\xff\xfeabc")


def test_clean_banner_truncates():
    banner = ports.clean_banner(b"A" * 1000)
    assert len(banner) == ports.BANNER_SHOWN_MAX + 3
    assert banner.endswith("...")


def test_clean_banner_blank_is_empty():
    assert ports.clean_banner(b"  \r\n") == ""


def test_open_port_with_banner():
    async def run():
        async def handler(reader, writer):
            writer.write(b"SSH-2.0-test\r\n")
            await writer.drain()
            writer.close()

        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        async with server:
            return port, await ports.scan_ports("127.0.0.1", [port])

    port, results = asyncio.run(run())
    assert results == [ports.PortResult(port, "open", "SSH-2.0-test")]


def test_open_port_without_banner():
    async def run():
        async def handler(reader, writer):
            await reader.read()
            writer.close()

        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        async with server:
            return port, await ports.scan_ports("127.0.0.1", [port], banner_wait=0.1)

    port, results = asyncio.run(run())
    assert results == [ports.PortResult(port, "open", None)]


def test_banner_flood_is_bounded():
    async def run():
        async def handler(reader, writer):
            writer.write(b"A" * 10000)
            await writer.drain()
            writer.close()

        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        async with server:
            return await ports.scan_ports("127.0.0.1", [port])

    (result,) = asyncio.run(run())
    assert result.state == "open"
    assert result.banner is not None
    assert len(result.banner) <= ports.BANNER_SHOWN_MAX + 3


def test_closed_port():
    (result,) = scan([free_port()])
    assert result.state == "closed"
    assert result.banner is None


def test_timeout_is_filtered(monkeypatch):
    async def hang(*args, **kwargs):
        await asyncio.sleep(30)

    monkeypatch.setattr(ports.asyncio, "open_connection", hang)
    results = scan([81], timeout=0.1)
    assert [(r.port, r.state) for r in results] == [(81, "filtered")]


def test_other_os_error_is_error_without_details(monkeypatch):
    async def boom(*args, **kwargs):
        raise OSError(113, "rahasia-detail-dari-sistem")

    monkeypatch.setattr(ports.asyncio, "open_connection", boom)
    results = scan([81])
    assert results[0].state == "error"
    assert "rahasia" not in repr(results)


def test_concurrency_never_exceeds_limit(monkeypatch):
    active = 0
    peak = 0

    async def slow_refuse(*args, **kwargs):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        try:
            await asyncio.sleep(0.01)
        finally:
            active -= 1
        raise ConnectionRefusedError

    monkeypatch.setattr(ports.asyncio, "open_connection", slow_refuse)
    results = scan(list(range(1, 61)), concurrency=5)
    assert len(results) == 60
    assert all(r.state == "closed" for r in results)
    assert 1 < peak <= 5


def test_results_sorted_and_deduplicated(monkeypatch):
    async def refuse(*args, **kwargs):
        raise ConnectionRefusedError

    monkeypatch.setattr(ports.asyncio, "open_connection", refuse)
    assert [r.port for r in scan([9, 3, 3, 7])] == [3, 7, 9]


@pytest.mark.parametrize("bad", [0, 65536, -1])
def test_scan_rejects_out_of_range_ports(bad):
    with pytest.raises(ports.PortSpecError):
        scan([bad])


@pytest.mark.parametrize(
    ("given", "expected"),
    [(0, 1), (-5, 1), (100, 100), (500, 500), (501, 500), (10**9, 500)],
)
def test_clamp_concurrency(given, expected):
    assert ports.clamp_concurrency(given) == expected


def test_clamp_timeout():
    assert ports.clamp_timeout(0) == ports.MIN_TIMEOUT
    assert ports.clamp_timeout(999) == ports.MAX_TIMEOUT
    assert ports.clamp_timeout(1.5) == 1.5


def test_run_scan_report_has_skipped_notes():
    report = ports.run_scan("localhost", "127.0.0.1", [free_port()])
    assert report.host == "localhost"
    assert report.address == "127.0.0.1"
    assert report.skipped == list(ports.SKIPPED)
    assert [r.state for r in report.results] == ["closed"]
