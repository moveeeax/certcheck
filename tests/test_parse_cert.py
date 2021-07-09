from datetime import datetime, timezone

import pytest

from certcheck.core import CertParseError, parse_cert
from tests.conftest import make_cert_dict


def test_extracts_common_name_and_issuer():
    cert = make_cert_dict(
        datetime(2021, 1, 1, tzinfo=timezone.utc),
        datetime(2022, 1, 1, tzinfo=timezone.utc),
        cn="host.example.com",
        issuer_cn="Example CA",
    )
    info = parse_cert(cert)
    assert info.common_name == "host.example.com"
    assert info.issuer_cn == "Example CA"


def test_extracts_dns_san():
    cert = make_cert_dict(
        datetime(2021, 1, 1, tzinfo=timezone.utc),
        datetime(2022, 1, 1, tzinfo=timezone.utc),
        san=("a.example.com", "b.example.com"),
    )
    info = parse_cert(cert)
    assert info.dns_names == ["a.example.com", "b.example.com"]


def test_parses_not_before_and_after():
    cert = make_cert_dict(
        datetime(2021, 1, 2, tzinfo=timezone.utc),
        datetime(2021, 12, 30, tzinfo=timezone.utc),
    )
    info = parse_cert(cert)
    assert info.not_before == datetime(2021, 1, 2, tzinfo=timezone.utc)
    assert info.not_after == datetime(2021, 12, 30, tzinfo=timezone.utc)


def test_serial_number_preserved():
    cert = make_cert_dict(
        datetime(2021, 1, 1, tzinfo=timezone.utc),
        datetime(2022, 1, 1, tzinfo=timezone.utc),
    )
    info = parse_cert(cert)
    assert info.serial_number == "01AB"


def test_non_dict_raises():
    with pytest.raises(CertParseError):
        parse_cert("not a dict")


def test_missing_not_after_raises():
    with pytest.raises(CertParseError):
        parse_cert({"subject": ((("commonName", "x"),),)})


def test_missing_san_gives_empty_list():
    cert = make_cert_dict(
        datetime(2021, 1, 1, tzinfo=timezone.utc),
        datetime(2022, 1, 1, tzinfo=timezone.utc),
    )
    del cert["subjectAltName"]
    info = parse_cert(cert)
    assert info.dns_names == []
