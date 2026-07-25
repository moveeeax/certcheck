import locale
from datetime import datetime, timezone

import pytest

from certcheck.core import MONTH_ABBRS, CertParseError, parse_asn1_time

# Locales whose month abbreviations differ from English; at least one is
# usually present on Linux CI images and macOS.
NON_ENGLISH_LOCALES = ("de_DE.UTF-8", "fr_FR.UTF-8", "es_ES.UTF-8", "ru_RU.UTF-8")


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


def test_all_month_abbreviations_parse():
    for number, name in enumerate(MONTH_ABBRS, start=1):
        dt = parse_asn1_time("%s 15 00:00:00 2021 GMT" % name)
        assert dt.month == number


def test_unknown_month_raises():
    with pytest.raises(CertParseError):
        parse_asn1_time("Foo  1 12:00:00 2021 GMT")


def test_out_of_range_day_raises():
    with pytest.raises(CertParseError):
        parse_asn1_time("Feb 30 12:00:00 2021 GMT")


def test_out_of_range_hour_raises():
    with pytest.raises(CertParseError):
        parse_asn1_time("Jun  1 25:00:00 2021 GMT")


def test_utc_suffix_accepted():
    dt = parse_asn1_time("Jun  1 12:00:00 2021 UTC")
    assert dt == datetime(2021, 6, 1, 12, 0, 0, tzinfo=timezone.utc)


def test_parsing_is_locale_independent():
    """Month names come from OpenSSL in English, never from LC_TIME.

    Regression test: parsing used strptime('%b'), which follows LC_TIME.
    Once a process had set a non-English locale -- as an embedding
    application may -- every certificate failed to parse with
    "bad time value". Python leaves LC_TIME at "C" by default, so this
    test must set the locale explicitly to reproduce it.
    """
    original = locale.setlocale(locale.LC_TIME)
    applied = None
    try:
        for candidate in NON_ENGLISH_LOCALES:
            try:
                locale.setlocale(locale.LC_TIME, candidate)
            except locale.Error:
                continue
            applied = candidate
            break
        if applied is None:
            pytest.skip("no non-English LC_TIME locale available")
        dt = parse_asn1_time("Jun  1 12:00:00 2021 GMT")
        assert dt == datetime(2021, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    finally:
        locale.setlocale(locale.LC_TIME, original)
