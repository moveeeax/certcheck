import json

from certcheck.cli import EXIT_BREACH, EXIT_ERROR, EXIT_OK, main
from tests.conftest import write_self_signed

JSON_KEYS = {
    "subject", "common_name", "issuer", "issuer_cn", "san",
    "serial_number", "not_before", "not_after", "days_until_expiry",
    "status", "breach", "target",
}


def test_check_file_exit_ok(tmp_path, openssl_required, capsys):
    path = write_self_signed(tmp_path, days_valid=365)
    rc = main(["check", "--file", path])
    out = capsys.readouterr().out
    assert rc == EXIT_OK
    assert "Status:" in out
    assert "valid" in out


def test_check_file_json_shape(tmp_path, openssl_required, capsys):
    path = write_self_signed(tmp_path, days_valid=365, cn="json.example.test")
    rc = main(["check", "--file", path, "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == EXIT_OK
    assert JSON_KEYS.issubset(payload.keys())
    assert payload["common_name"] == "json.example.test"
    assert payload["status"] == "valid"
    assert payload["breach"] is False
    assert isinstance(payload["san"], list)


def test_check_file_expiring_exit_breach(tmp_path, openssl_required, capsys):
    # A 365-day cert is 'expiring' when the warn window is huge.
    path = write_self_signed(tmp_path, days_valid=365)
    rc = main(["check", "--file", path, "--warn-days", "1000"])
    out = capsys.readouterr().out
    assert rc == EXIT_BREACH
    assert "expiring" in out


def test_check_requires_target_or_file(capsys):
    rc = main(["check"])
    err = capsys.readouterr().err
    assert rc == EXIT_ERROR
    assert "required" in err


def test_check_missing_file_json_error(capsys):
    rc = main(["check", "--file", "/no/such/file.pem", "--json"])
    err = capsys.readouterr().err
    assert rc == EXIT_ERROR
    assert json.loads(err)["error"]


def test_no_subcommand_returns_error(capsys):
    rc = main([])
    assert rc == EXIT_ERROR
