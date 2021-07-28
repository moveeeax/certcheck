import pytest

from certcheck.cli import CertCheckError, decode_cert_file
from certcheck.core import evaluate, parse_cert
from tests.conftest import write_self_signed


def test_decode_real_pem(tmp_path, openssl_required):
    path = write_self_signed(tmp_path, days_valid=365, cn="file.example.test")
    raw = decode_cert_file(path)
    info = parse_cert(raw)
    assert info.common_name == "file.example.test"
    assert "file.example.test" in info.dns_names
    assert "www.file.example.test" in info.dns_names


def test_decoded_pem_is_currently_valid(tmp_path, openssl_required):
    path = write_self_signed(tmp_path, days_valid=365)
    info = parse_cert(decode_cert_file(path))
    status = evaluate(info, warn_days=30)
    assert status.status == "valid"
    assert status.breach is False


def test_missing_file_raises():
    with pytest.raises(CertCheckError):
        decode_cert_file("/no/such/cert.pem")


def test_garbage_file_raises(tmp_path):
    bad = tmp_path / "bad.pem"
    bad.write_text("this is not a certificate\n")
    with pytest.raises(CertCheckError):
        decode_cert_file(str(bad))
