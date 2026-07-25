import json

import pytest

from certcheck.cli import EXIT_ERROR, EXIT_OK, main
from tests.conftest import write_self_signed


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "certcheck" in out


def test_help_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "check" in out
    assert "batch" in out


def test_negative_warn_days_rejected(tmp_path, openssl_required, capsys):
    path = write_self_signed(tmp_path, days_valid=365)
    rc = main(["check", "--file", path, "--warn-days", "-1"])
    err = capsys.readouterr().err
    assert rc == EXIT_ERROR
    assert "non-negative" in err


# Bad --timeout / --port values must be rejected before any socket call.
# A non-positive timeout used to reach socket.create_connection and raise
# an unhandled ValueError ("Timeout value out of range"); an out-of-range
# port surfaced as a misleading DNS lookup failure. Neither used the
# documented "error: ..." / exit-2 contract.
@pytest.mark.parametrize("timeout", ["0", "-1", "-0.5"])
def test_non_positive_timeout_rejected(timeout, capsys):
    rc = main(["check", "example.invalid", "--timeout", timeout])
    err = capsys.readouterr().err
    assert rc == EXIT_ERROR
    assert "--timeout" in err


@pytest.mark.parametrize("port", ["0", "-1", "65536", "99999"])
def test_out_of_range_port_rejected(port, capsys):
    rc = main(["check", "example.invalid", "--port", port])
    err = capsys.readouterr().err
    assert rc == EXIT_ERROR
    assert "--port" in err


def test_bad_option_error_honours_json_flag(capsys):
    rc = main(["check", "example.invalid", "--timeout", "0", "--json"])
    err = capsys.readouterr().err
    assert rc == EXIT_ERROR
    assert "--timeout" in json.loads(err)["error"]


def test_batch_also_validates_options(tmp_path, capsys):
    hosts = tmp_path / "hosts.txt"
    hosts.write_text("example.invalid\n", encoding="utf-8")
    rc = main(["batch", "--file", str(hosts), "--timeout", "0"])
    err = capsys.readouterr().err
    assert rc == EXIT_ERROR
    assert "--timeout" in err


def test_valid_options_are_accepted(tmp_path, openssl_required, capsys):
    """Guard against the validator rejecting legitimate values."""
    path = write_self_signed(tmp_path, days_valid=365)
    rc = main(["check", "--file", path, "--timeout", "0.5",
               "--port", "65535", "--warn-days", "0"])
    capsys.readouterr()
    assert rc == EXIT_OK
