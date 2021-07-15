import pytest

from certcheck.cli import CertCheckError, parse_target


def test_bare_host_uses_default_port():
    assert parse_target("example.com") == ("example.com", 443)


def test_custom_default_port():
    assert parse_target("example.com", default_port=8443) == ("example.com", 8443)


def test_ipv4_host_port():
    assert parse_target("10.0.0.1:8443") == ("10.0.0.1", 8443)


def test_hostname_with_port():
    assert parse_target("mail.example.com:993") == ("mail.example.com", 993)


def test_bracketed_ipv6_with_port():
    assert parse_target("[::1]:443") == ("::1", 443)


def test_bracketed_ipv6_without_port():
    assert parse_target("[2001:db8::1]") == ("2001:db8::1", 443)


def test_bare_ipv6_treated_as_host():
    assert parse_target("2001:db8::1") == ("2001:db8::1", 443)


def test_empty_raises():
    with pytest.raises(CertCheckError):
        parse_target("   ")


def test_invalid_port_raises():
    with pytest.raises(CertCheckError):
        parse_target("example.com:notaport")


def test_port_out_of_range_raises():
    with pytest.raises(CertCheckError):
        parse_target("example.com:70000")


def test_missing_host_raises():
    with pytest.raises(CertCheckError):
        parse_target(":443")
