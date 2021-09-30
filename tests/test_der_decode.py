import ssl

from certcheck.cli import _decode_der, decode_cert_file
from certcheck.core import parse_cert
from tests.conftest import write_self_signed


def test_der_roundtrip_matches_pem(tmp_path, openssl_required):
    pem_path = write_self_signed(tmp_path, days_valid=365, cn="der.example.test")

    with open(pem_path, "r") as handle:
        pem_text = handle.read()
    der = ssl.PEM_cert_to_DER_cert(pem_text)

    from_der = parse_cert(_decode_der(der))
    from_pem = parse_cert(decode_cert_file(pem_path))

    assert from_der.common_name == from_pem.common_name == "der.example.test"
    assert from_der.dns_names == from_pem.dns_names
    assert from_der.not_after == from_pem.not_after
