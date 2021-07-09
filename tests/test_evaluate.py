from datetime import datetime, timedelta, timezone

from certcheck.core import (
    EXPIRED,
    EXPIRING,
    NOT_YET_VALID,
    VALID,
    evaluate,
    parse_cert,
)
from tests.conftest import make_cert_dict

NOW = datetime(2021, 6, 1, 12, 0, 0, tzinfo=timezone.utc)


def _info(days_from_now, lifetime_days=365):
    not_after = NOW + timedelta(days=days_from_now)
    not_before = not_after - timedelta(days=lifetime_days)
    return parse_cert(make_cert_dict(not_before, not_after))


def test_valid_cert_far_from_expiry():
    status = evaluate(_info(200), warn_days=30, now=NOW)
    assert status.status == VALID
    assert status.breach is False
    assert status.days_until_expiry == 200


def test_expiring_cert_within_window():
    status = evaluate(_info(10), warn_days=30, now=NOW)
    assert status.status == EXPIRING
    assert status.breach is True


def test_expired_cert():
    status = evaluate(_info(-5), warn_days=30, now=NOW)
    assert status.status == EXPIRED
    assert status.breach is True
    assert status.expired is True
    assert status.days_until_expiry < 0


def test_not_yet_valid_cert():
    not_before = NOW + timedelta(days=5)
    not_after = NOW + timedelta(days=400)
    info = parse_cert(make_cert_dict(not_before, not_after))
    status = evaluate(info, warn_days=30, now=NOW)
    assert status.status == NOT_YET_VALID
    assert status.breach is True


def test_boundary_exactly_warn_days_is_valid():
    # Exactly 30 whole days out -> still valid (strict boundary).
    status = evaluate(_info(30), warn_days=30, now=NOW)
    assert status.status == VALID
    assert status.days_until_expiry == 30


def test_boundary_just_inside_window_is_expiring():
    not_after = NOW + timedelta(days=29, hours=23)
    not_before = not_after - timedelta(days=365)
    info = parse_cert(make_cert_dict(not_before, not_after))
    status = evaluate(info, warn_days=30, now=NOW)
    assert status.status == EXPIRING
    assert status.days_until_expiry == 29


def test_custom_warn_days():
    status = evaluate(_info(45), warn_days=60, now=NOW)
    assert status.status == EXPIRING


def test_naive_now_is_treated_as_utc():
    naive_now = datetime(2021, 6, 1, 12, 0, 0)
    status = evaluate(_info(100), warn_days=30, now=naive_now)
    assert status.status == VALID
