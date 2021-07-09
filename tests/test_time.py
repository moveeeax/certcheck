from datetime import datetime, timezone

import pytest

from certcheck.core import CertParseError, parse_asn1_time


def test_parses_gmt_time():
    dt = parse_asn1_time("Jun  1 12:00:00 2021 GMT")
    assert dt == datetime(2021, 6, 1, 12, 0, 0, tzinfo=timezone.utc)


def test_parses_double_digit_day():
    dt = parse_asn1_time("Dec 31 23:59:59 2021 GMT")
    assert dt.day == 31
    assert dt.month == 12
    assert dt.tzinfo == timezone.utc


def test_result_is_timezone_aware():
    dt = parse_asn1_time("Jan  1 00:00:00 2022 GMT")
    assert dt.tzinfo is not None
    assert dt.utcoffset().total_seconds() == 0


def test_empty_value_raises():
    with pytest.raises(CertParseError):
        parse_asn1_time("")


def test_garbage_value_raises():
    with pytest.raises(CertParseError):
        parse_asn1_time("not a date at all")
