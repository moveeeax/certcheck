import socket
import ssl
import threading

import pytest

from certcheck.cli import EXIT_BREACH, EXIT_OK, fetch_cert, main
from certcheck.core import evaluate, parse_cert
from tests.conftest import write_self_signed


class _TLSServer:
    """A minimal single-threaded TLS server on 127.0.0.1 for tests."""

    def __init__(self, certfile, keyfile):
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(certfile=certfile, keyfile=keyfile)
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


def test_secure_fetch_rejects_self_signed(tls_server):
    from certcheck.cli import CertCheckError
    with pytest.raises(CertCheckError):
        fetch_cert("127.0.0.1", tls_server.port, timeout=5, insecure=False)
