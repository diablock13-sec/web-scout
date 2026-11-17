import socket
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest

from web_scout.client import USER_AGENT, Fetcher, FetchError, describe_error
from web_scout.scope import Scope


@pytest.fixture
def lab():
    """Server HTTP sungguhan di loopback. Mencatat (path, header Host, User-Agent)."""
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append((self.path, self.headers.get("Host"), self.headers.get("User-Agent")))
            body = b"halo dari lab"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            return None

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server.server_address[1], seen
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)


# ---- koneksi sungguhan ----


def test_real_get_over_a_real_socket(lab):
    port, seen = lab
    with Fetcher(Scope(), min_interval=0) as f:
        response = f.get(f"http://127.0.0.1:{port}/x?y=1", max_body=100)
    assert response.status == 200
    assert response.body == b"halo dari lab"
    assert response.headers["x-content-type-options"] == "nosniff"
    path, host, agent = seen[0]
    assert path == "/x?y=1"
    assert host == f"127.0.0.1:{port}"
    assert agent == USER_AGENT


def test_hostname_is_pinned_to_verified_address_but_kept_in_host_header(lab):
    port, seen = lab
    with Fetcher(Scope(), min_interval=0, resolver=lambda host: ["127.0.0.1"]) as f:
        f.get(f"http://localhost:{port}/")
    assert seen[0][1] == f"localhost:{port}"


def test_connection_refused_is_reported_clearly_without_details():
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()  # tidak ada yang mendengarkan di port ini
    with Fetcher(Scope(), min_interval=0) as f, pytest.raises(FetchError) as info:
        f.get(f"http://127.0.0.1:{port}/")
    assert str(info.value) == "koneksi ditolak (tidak ada yang mendengarkan di port itu)"


@pytest.mark.parametrize("address", [("203.0.113.9", 80), ("example.com", 80)])
def test_tests_cannot_reach_beyond_loopback(address):
    with pytest.raises(AssertionError, match="test mencoba"):
        socket.create_connection(address, timeout=1)


# ---- ringkasan galat ----


def chained(outer, cause):
    outer.__cause__ = cause
    return outer


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (
            chained(httpx.ConnectError("x"), ConnectionRefusedError("rahasia")),
            "koneksi ditolak (tidak ada yang mendengarkan di port itu)",
        ),
        (chained(httpx.ConnectError("x"), ConnectionResetError("rahasia")), "koneksi diputus oleh server"),
        (chained(httpx.ConnectError("x"), ssl.SSLCertVerificationError("rahasia")), "sertifikat TLS tidak valid"),
        (chained(httpx.ConnectError("x"), ssl.SSLError("rahasia")), "kegagalan TLS"),
        (httpx.ConnectError("rahasia"), "gagal terhubung (ConnectError)"),
        (httpx.ReadError("rahasia"), "gagal terhubung (ReadError)"),
    ],
)
def test_describe_error(error, expected):
    message = describe_error(error)
    assert message == expected
    assert "rahasia" not in message


def test_describe_error_survives_a_circular_cause_chain():
    error = httpx.ConnectError("x")
    error.__cause__ = error
    assert describe_error(error) == "gagal terhubung (ConnectError)"
