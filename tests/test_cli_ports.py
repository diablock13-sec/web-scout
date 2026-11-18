import json
import socket

import pytest

from web_scout.cli import main


@pytest.fixture
def listener():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen()
    yield srv.getsockname()[1]
    srv.close()


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_open_port_is_listed_and_exit_zero(listener, capsys):
    rc = main(["ports", "http://127.0.0.1/", "--ports", str(listener)])
    out = capsys.readouterr().out
    assert rc == 0
    assert f"{listener}/tcp" in out
    assert "1 open" in out
    assert "bukan temuan" in out


def test_json_output(listener, capsys):
    rc = main(["ports", "http://127.0.0.1/", "--ports", str(listener), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert data["address"] == "127.0.0.1"
    assert data["results"][0]["port"] == listener
    assert data["results"][0]["state"] == "open"


def test_closed_port_reports_none_open(capsys):
    rc = main(["ports", "http://127.0.0.1/", "--ports", str(free_port())])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Tidak ada port terbuka" in out


def test_port_in_url_is_scanned_by_default(listener, capsys):
    rc = main(["ports", f"http://127.0.0.1:{listener}/", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert rc == 0
    opened = [r["port"] for r in data["results"] if r["state"] == "open"]
    assert listener in opened


def test_localhost_is_in_scope(listener, capsys):
    rc = main(["ports", f"http://localhost:{listener}/", "--ports", str(listener)])
    assert rc == 0
    assert "1 open" in capsys.readouterr().out


@pytest.mark.parametrize(
    "url", ["http://example.com/", "http://192.168.1.10/", "http://10.0.0.5/"]
)
def test_out_of_scope_target_is_refused_before_any_connection(url, capsys):
    # conftest membuat test gagal kalau ada resolve atau koneksi ke luar loopback
    rc = main(["ports", url])
    assert rc == 2
    assert "di luar lingkup" in capsys.readouterr().err


def test_allow_option_does_not_exist_for_ports():
    with pytest.raises(SystemExit) as exc:
        main(["ports", "http://127.0.0.1/", "--allow", "lab.example", "--i-own-this"])
    assert exc.value.code == 2


@pytest.mark.parametrize("spec", ["0", "65536", "abc", "3-1"])
def test_bad_port_spec_is_an_error(spec, capsys):
    rc = main(["ports", "http://127.0.0.1/", "--ports", spec])
    assert rc == 2
    assert capsys.readouterr().err.startswith("web-scout:")


def test_huge_concurrency_is_clamped_not_crashing(listener, capsys):
    rc = main(
        ["ports", "http://127.0.0.1/", "--ports", str(listener), "--concurrency", "99999999"]
    )
    assert rc == 0
    assert "1 open" in capsys.readouterr().out
