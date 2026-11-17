import socket

import pytest

LOOPBACK = {"127.0.0.1", "::1", "localhost"}
_real_getaddrinfo = socket.getaddrinfo
_real_connect = socket.socket.connect


@pytest.fixture(autouse=True)
def only_loopback_network(monkeypatch):
    """Test hanya boleh menyentuh loopback. Resolve atau koneksi ke tempat lain
    langsung menggagalkan test."""

    def getaddrinfo(host, *args, **kwargs):
        if host in LOOPBACK:
            return _real_getaddrinfo(host, *args, **kwargs)
        raise AssertionError(f"test mencoba resolve {host!r}")

    def connect(self, address):
        host = address[0] if isinstance(address, tuple) else address
        if host in LOOPBACK:
            return _real_connect(self, address)
        raise AssertionError(f"test mencoba terhubung ke {address!r}")

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    monkeypatch.setattr(socket.socket, "connect", connect)
