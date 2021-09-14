import json
from datetime import datetime, timezone

from certcheck.core import evaluate, parse_cert, status_report
from tests.conftest import make_cert_dict

NOW = datetime(2021, 6, 1, tzinfo=timezone.utc)


def _report(days_out):
    from datetime import timedelta
    not_after = NOW + timedelta(days=days_out)
    not_before = not_after - timedelta(days=365)
    info = parse_cert(make_cert_dict(not_before, not_after, cn="rep.example"))
    status = evaluate(info, warn_days=30, now=NOW)
    return status_report(info, status)


def test_report_is_json_serializable():
    report = _report(100)
    text = json.dumps(report)
    assert json.loads(text) == report


def test_report_iso_timestamps():
    report = _report(100)
    assert report["not_after"].endswith("+00:00")
    assert report["not_before"].endswith("+00:00")


def test_report_contains_expected_fields():
    report = _report(100)
    for key in ("common_name", "issuer_cn", "san", "status", "breach",
                "days_until_expiry", "serial_number"):
        assert key in report


def test_report_breach_flag_matches_status():
    valid = _report(200)
    expiring = _report(5)
    assert valid["breach"] is False
    assert expiring["breach"] is True
    assert expiring["status"] == "expiring"
