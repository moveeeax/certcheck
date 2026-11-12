import json
import socket
import ssl
import threading

import pytest

from certcheck.cli import EXIT_BREACH, EXIT_ERROR, EXIT_OK, fetch_cert, fetch_peer, main
from certcheck.core import X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT, evaluate, parse_cert
from tests.conftest import write_ca_chain, write_self_signed


class _TLSServer:
    """A minimal single-threaded TLS server on 127.0.0.1 for tests."""

    def __init__(self, certfile, keyfile, maximum_version=None):
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(certfile=certfile, keyfile=keyfile)
        if maximum_version is not None:
            self.context.maximum_version = maximum_version
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self):
        while not self._stop.is_set():
            try:
                self.sock.settimeout(0.5)
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                tls = self.context.wrap_socket(conn, server_side=True)
                tls.close()
            except (ssl.SSLError, OSError):
                try:
                    conn.close()
                except OSError:
                    pass

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        try:
            self.sock.close()
        except OSError:
            pass
        self._thread.join(timeout=2)


@pytest.fixture
def tls_server(tmp_path, openssl_required):
    cert = write_self_signed(tmp_path, days_valid=365, cn="127.0.0.1")
    key = str(tmp_path / "key.pem")
    with _TLSServer(cert, key) as server:
        yield server


def test_fetch_cert_from_live_server(tls_server):
    raw = fetch_cert("127.0.0.1", tls_server.port, timeout=5, insecure=True)
    info = parse_cert(raw)
    assert info.common_name == "127.0.0.1"
    status = evaluate(info, warn_days=30)
    assert status.status == "valid"


def test_check_command_against_live_server(tls_server, capsys):
    rc = main([
        "check", "127.0.0.1:%d" % tls_server.port, "--insecure", "--json",
    ])
    import json
    payload = json.loads(capsys.readouterr().out)
    assert rc == EXIT_OK
    assert payload["common_name"] == "127.0.0.1"
    assert payload["status"] == "valid"


def test_check_live_server_expiring_breaches(tls_server, capsys):
    rc = main([
        "check", "127.0.0.1:%d" % tls_server.port,
        "--insecure", "--warn-days", "1000",
    ])
    assert rc == EXIT_BREACH


def test_secure_fetch_reads_self_signed_and_records_why(tls_server):
    # Verification fails, but the certificate is still read over a
    # second, unverified connection instead of aborting.
    peer = fetch_peer("127.0.0.1", tls_server.port, timeout=5)
    assert peer.verify_code == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT
    assert "self-signed" in peer.verify_error
    assert parse_cert(peer.cert).common_name == "127.0.0.1"


def test_check_reports_untrusted_with_dates(tls_server, capsys):
    rc = main(["check", "127.0.0.1:%d" % tls_server.port, "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == EXIT_BREACH
    assert payload["status"] == "untrusted"
    assert payload["breach"] is True
    assert payload["not_after"]
    assert payload["days_until_expiry"] > 300
    assert "self-signed" in payload["verify_error"]


def test_check_human_output_shows_verify_error(tls_server, capsys):
    rc = main(["check", "127.0.0.1:%d" % tls_server.port])
    out = capsys.readouterr().out
    assert rc == EXIT_BREACH
    assert "Status:      untrusted" in out
    assert "Verify:" in out


def test_insecure_does_not_judge_trust(tls_server, capsys):
    rc = main(["check", "127.0.0.1:%d" % tls_server.port, "--insecure", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == EXIT_OK
    assert payload["status"] == "valid"
    assert "verify_error" not in payload


@pytest.fixture
def ca_chain(tmp_path, openssl_required):
    return write_ca_chain(tmp_path, leaf_cn="other.test", leaf_san="DNS:other.test")


def test_hostname_mismatch_is_reported(ca_chain, capsys):
    with _TLSServer(ca_chain["bundle"], ca_chain["leaf_key"]) as server:
        rc = main(["check", "127.0.0.1:%d" % server.port, "--ca-file", ca_chain["root"],
                   "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == EXIT_BREACH
    assert payload["status"] == "hostname_mismatch"
    assert payload["common_name"] == "other.test"
    assert payload["verify_error"]


def test_ca_file_makes_private_chain_valid(tmp_path, openssl_required, capsys):
    chain = write_ca_chain(tmp_path)
    with _TLSServer(chain["bundle"], chain["leaf_key"]) as server:
        rc = main(["check", "127.0.0.1:%d" % server.port, "--ca-file", chain["root"],
                   "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == EXIT_OK
    assert payload["status"] == "valid"
    assert "verify_error" not in payload


def test_missing_ca_file_is_an_error(tls_server, capsys):
    rc = main(["check", "127.0.0.1:%d" % tls_server.port, "--ca-file", "/no/such/ca.pem"])
    assert rc == EXIT_ERROR
    assert "CA file" in capsys.readouterr().err
