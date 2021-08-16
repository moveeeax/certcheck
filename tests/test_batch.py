import json

import pytest

from certcheck.cli import EXIT_BREACH, EXIT_ERROR, EXIT_OK, main
from tests.conftest import write_self_signed
from tests.test_live_server import _TLSServer


@pytest.fixture
def server(tmp_path, openssl_required):
    cert = write_self_signed(tmp_path, days_valid=365, cn="127.0.0.1")
    key = str(tmp_path / "key.pem")
    with _TLSServer(cert, key) as srv:
        yield srv


def _hosts_file(tmp_path, lines):
    path = tmp_path / "hosts.txt"
    path.write_text("\n".join(lines) + "\n")
    return str(path)


def test_batch_all_valid(server, tmp_path, capsys):
    hosts = _hosts_file(tmp_path, [
        "# a comment line",
        "127.0.0.1:%d" % server.port,
        "",
        "127.0.0.1:%d" % server.port,
    ])
    rc = main(["batch", "--file", hosts, "--insecure", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == EXIT_OK
    assert len(payload) == 2
    assert all(item["status"] == "valid" for item in payload)


def test_batch_breach_when_expiring(server, tmp_path, capsys):
    hosts = _hosts_file(tmp_path, ["127.0.0.1:%d" % server.port])
    rc = main(["batch", "--file", hosts, "--insecure", "--warn-days", "1000"])
    out = capsys.readouterr().out
    assert rc == EXIT_BREACH
    assert "EXPIRING" in out


def test_batch_reports_unreachable_as_error(server, tmp_path, capsys):
    hosts = _hosts_file(tmp_path, [
        "127.0.0.1:%d" % server.port,
        "127.0.0.1:1",  # nothing listening on port 1
    ])
    rc = main(["batch", "--file", hosts, "--insecure", "--json", "--timeout", "2"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == EXIT_BREACH
    statuses = {item["status"] for item in payload}
    assert "error" in statuses
    assert "valid" in statuses


def test_batch_missing_file(capsys):
    rc = main(["batch", "--file", "/no/such/hosts.txt"])
    assert rc == EXIT_ERROR


def test_batch_human_output_format(server, tmp_path, capsys):
    hosts = _hosts_file(tmp_path, ["127.0.0.1:%d" % server.port])
    rc = main(["batch", "--file", hosts, "--insecure"])
    out = capsys.readouterr().out
    assert rc == EXIT_OK
    assert "VALID" in out
    assert "days" in out
