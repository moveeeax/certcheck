import pytest

from certcheck.cli import EXIT_ERROR, main
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
