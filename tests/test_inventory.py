import json
import ssl

import pytest

from certcheck.cli import EXIT_BREACH, EXIT_ERROR, EXIT_OK, main
from tests.conftest import write_ca_chain, write_self_signed
from tests.test_live_server import _TLSServer


def _hosts_file(tmp_path, lines):
    path = tmp_path / "hosts.txt"
    path.write_text("\n".join(lines) + "\n")
    return str(path)


def _run(capsys, *argv):
    rc = main(["inventory", *argv, "--json", "--timeout", "5"])
    return rc, json.loads(capsys.readouterr().out)


def _checks(report):
    return [f["check"] for f in report["findings"]]


@pytest.fixture
def chain(tmp_path, openssl_required):
    return write_ca_chain(tmp_path)


def test_inventory_private_chain_is_clean(chain, tmp_path, capsys):
    with _TLSServer(chain["bundle"], chain["leaf_key"]) as server:
        hosts = _hosts_file(tmp_path, ["127.0.0.1:%d" % server.port])
        rc, payload = _run(capsys, "--file", hosts, "--ca-file", chain["root"])
    report = payload[0]
    assert rc == EXIT_OK, report
    assert report["status"] == "valid"
    assert report["findings"] == []
    assert [c["common_name"] for c in report["chain"]] == ["127.0.0.1", "Test Intermediate CA"]
    assert report["chain"][1]["issuer_cn"] == "Test Root CA"
    assert report["protocols"]["TLSv1.2"] is True
    assert report["protocols"]["TLSv1.3"] is True


def test_inventory_detects_incomplete_chain(chain, tmp_path, capsys):
    # The server sends only the leaf; the client trusts the root but
    # cannot reach it without the intermediate.
    with _TLSServer(chain["leaf"], chain["leaf_key"]) as server:
        hosts = _hosts_file(tmp_path, ["127.0.0.1:%d" % server.port])
        rc, payload = _run(capsys, "--file", hosts, "--ca-file", chain["root"])
    report = payload[0]
    assert rc == EXIT_BREACH
    assert report["status"] == "untrusted"
    assert _checks(report) == ["incomplete_chain"]
    assert len(report["chain"]) == 1


def test_inventory_detects_self_signed(tmp_path, openssl_required, capsys):
    cert = write_self_signed(tmp_path, cn="127.0.0.1")
    with _TLSServer(cert, str(tmp_path / "key.pem")) as server:
        hosts = _hosts_file(tmp_path, ["127.0.0.1:%d" % server.port])
        rc, payload = _run(capsys, "--file", hosts)
    assert rc == EXIT_BREACH
    assert _checks(payload[0]) == ["self_signed"]


def test_inventory_insecure_skips_trust_findings(tmp_path, openssl_required, capsys):
    cert = write_self_signed(tmp_path, cn="127.0.0.1")
    with _TLSServer(cert, str(tmp_path / "key.pem")) as server:
        hosts = _hosts_file(tmp_path, ["127.0.0.1:%d" % server.port])
        rc, payload = _run(capsys, "--file", hosts, "--insecure")
    assert rc == EXIT_OK
    assert payload[0]["findings"] == []


def test_inventory_min_version_policy(chain, tmp_path, capsys):
    with _TLSServer(chain["bundle"], chain["leaf_key"],
                    maximum_version=ssl.TLSVersion.TLSv1_2) as server:
        hosts = _hosts_file(tmp_path, ["127.0.0.1:%d" % server.port])
        rc, payload = _run(capsys, "--file", hosts, "--ca-file", chain["root"],
                           "--min-version", "tls1.3")
    report = payload[0]
    assert rc == EXIT_BREACH
    assert report["protocols"]["TLSv1.3"] is False
    assert report["protocols"]["TLSv1.2"] is True
    assert "TLSv1.2 accepted" in report["findings"][0]["detail"]


def test_inventory_lists_ciphers(chain, tmp_path, capsys):
    with _TLSServer(chain["bundle"], chain["leaf_key"]) as server:
        server.context.set_ciphers("ECDHE-RSA-AES128-GCM-SHA256:AES128-GCM-SHA256")
        hosts = _hosts_file(tmp_path, ["127.0.0.1:%d" % server.port])
        rc, payload = _run(capsys, "--file", hosts, "--ca-file", chain["root"],
                           "--ciphers", "--require-forward-secrecy")
    report = payload[0]
    by_name = {c["name"]: c for c in report["ciphers"]}
    assert by_name["ECDHE-RSA-AES128-GCM-SHA256"]["forward_secrecy"] is True
    assert by_name["AES128-GCM-SHA256"]["forward_secrecy"] is False
    assert not any(c["protocol"] == "TLSv1.2" and c["name"].startswith("ECDHE-ECDSA")
                   for c in report["ciphers"])
    assert any(c["protocol"] == "TLSv1.3" and c["forward_secrecy"] for c in report["ciphers"])
    assert rc == EXIT_BREACH
    assert _checks(report) == ["forward_secrecy"]


def test_inventory_keeps_order_and_reports_errors(chain, tmp_path, capsys):
    with _TLSServer(chain["bundle"], chain["leaf_key"]) as server:
        good = "127.0.0.1:%d" % server.port
        hosts = _hosts_file(tmp_path, ["127.0.0.1:1", good, "127.0.0.1:1", good])
        rc, payload = _run(capsys, "--file", hosts, "--ca-file", chain["root"],
                           "--concurrency", "4")
    assert rc == EXIT_BREACH
    assert [r["status"] for r in payload] == ["error", "valid", "error", "valid"]


def test_inventory_human_output(chain, tmp_path, capsys):
    with _TLSServer(chain["leaf"], chain["leaf_key"]) as server:
        hosts = _hosts_file(tmp_path, ["127.0.0.1:%d" % server.port])
        rc = main(["inventory", "--file", hosts, "--ca-file", chain["root"]])
    out = capsys.readouterr().out
    assert rc == EXIT_BREACH
    assert "UNTRUSTED" in out
    assert "TLSv1.2" in out
    assert "! incomplete_chain:" in out


@pytest.mark.parametrize("argv, message", [
    (["--concurrency", "0"], "--concurrency"),
    (["--require-forward-secrecy"], "--ciphers"),
])
def test_inventory_option_validation(argv, message, tmp_path, capsys):
    hosts = _hosts_file(tmp_path, ["example.invalid"])
    rc = main(["inventory", "--file", hosts, *argv])
    assert rc == EXIT_ERROR
    assert message in capsys.readouterr().err


def test_inventory_rejects_unknown_min_version(tmp_path, capsys):
    hosts = _hosts_file(tmp_path, ["example.invalid"])
    with pytest.raises(SystemExit) as exc:
        main(["inventory", "--file", hosts, "--min-version", "ssl3"])
    assert exc.value.code == 2


def test_inventory_missing_file(capsys):
    assert main(["inventory", "--file", "/no/such/hosts.txt"]) == EXIT_ERROR
