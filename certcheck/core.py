"""Pure certificate parsing and expiry-threshold logic.

This module performs no network or filesystem I/O. It operates on the
plain ``dict`` structure produced by :func:`ssl.SSLSocket.getpeercert`
and :func:`ssl._ssl._test_decode_cert`, so it is fully unit-testable
without a live TLS connection.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

VALID = "valid"
EXPIRING = "expiring"
EXPIRED = "expired"
NOT_YET_VALID = "not_yet_valid"


class CertParseError(ValueError):
    """Raised when a certificate dict cannot be understood."""


MONTH_ABBRS = (
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
)

_MONTHS = {name: number for number, name in enumerate(MONTH_ABBRS, start=1)}


def parse_asn1_time(value: str) -> datetime:
    """Parse an OpenSSL ASN.1 time string into an aware UTC datetime.

    Example input: ``'Jun  1 12:00:00 2021 GMT'`` (note the padding
    space for single-digit days).

    The month is resolved through an explicit English table rather than
    ``strptime``'s ``%b``, which follows ``LC_TIME``. OpenSSL always
    emits English month abbreviations, so parsing them must not be
    localized: a process that has called ``locale.setlocale`` for a
    non-English locale -- as an application embedding this package may
    well have done -- otherwise fails to parse every certificate.
    (Environment variables alone do not trigger this, since Python
    leaves ``LC_TIME`` at ``C`` unless asked otherwise.)
    """
    if not value:
        raise CertParseError("empty time value")
    text = value.strip()
    if text.endswith(" GMT") or text.endswith(" UTC"):
        text = text[:-4].strip()

    parts = text.split()
    if len(parts) != 4:
        raise CertParseError("bad time value: %r" % value)
    month_name, day_text, clock, year_text = parts

    month = _MONTHS.get(month_name)
    if month is None:
        raise CertParseError("bad time value: %r" % value)

    try:
        hour_text, minute_text, second_text = clock.split(":")
        return datetime(
            int(year_text),
            month,
            int(day_text),
            int(hour_text),
            int(minute_text),
            int(second_text),
            tzinfo=timezone.utc,
        )
    except ValueError as exc:
        raise CertParseError("bad time value: %r" % value) from exc


def _name_to_dict(rdns) -> Dict[str, str]:
    """Flatten the nested RDN tuple structure into a simple dict.

    ``getpeercert`` returns names as ``((('commonName', 'x'),), ...)``.
    The first value seen for a given attribute wins.
    """
    out: Dict[str, str] = {}
    for rdn in rdns or ():
        for pair in rdn:
            if len(pair) != 2:
                continue
            key, val = pair
            out.setdefault(key, val)
    return out


@dataclass
class CertInfo:
    subject: Dict[str, str] = field(default_factory=dict)
    issuer: Dict[str, str] = field(default_factory=dict)
    san: List[Tuple[str, str]] = field(default_factory=list)
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    serial_number: Optional[str] = None

    @property
    def common_name(self) -> Optional[str]:
        return self.subject.get("commonName")

    @property
    def issuer_cn(self) -> Optional[str]:
        return self.issuer.get("commonName")

    @property
    def dns_names(self) -> List[str]:
        return [val for (kind, val) in self.san if kind == "DNS"]


def parse_cert(cert: Dict) -> CertInfo:
    """Turn a getpeercert-style dict into a :class:`CertInfo`."""
    if not isinstance(cert, dict):
        raise CertParseError("certificate must be a dict, got %r" % type(cert))
    if "notAfter" not in cert:
        raise CertParseError("certificate has no notAfter field")

    not_after = parse_asn1_time(cert["notAfter"])
    not_before = parse_asn1_time(cert["notBefore"]) if cert.get("notBefore") else None
    san = [tuple(item) for item in cert.get("subjectAltName", ()) if len(item) == 2]

    return CertInfo(
        subject=_name_to_dict(cert.get("subject")),
        issuer=_name_to_dict(cert.get("issuer")),
        san=san,
        not_before=not_before,
        not_after=not_after,
        serial_number=cert.get("serialNumber"),
    )


@dataclass
class ExpiryStatus:
    status: str
    days_until_expiry: int
    breach: bool
    not_after: Optional[datetime] = None

    @property
    def expired(self) -> bool:
        return self.status == EXPIRED


def evaluate(info: CertInfo, warn_days: int = 30, now: Optional[datetime] = None) -> ExpiryStatus:
    """Classify a certificate's validity relative to ``now``.

    Returns an :class:`ExpiryStatus`. ``breach`` is True whenever the
    certificate is not plainly valid, i.e. the CLI should exit non-zero.
    The expiring boundary is strict: a cert exactly ``warn_days`` away
    (whole days) is still ``valid``.
    """
    if info.not_after is None:
        raise CertParseError("cert has no notAfter to evaluate")
    if now is None:
        now = datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)

    days_until = (info.not_after - now).days

    if now >= info.not_after:
        status = EXPIRED
    elif info.not_before is not None and now < info.not_before:
        status = NOT_YET_VALID
    elif days_until < warn_days:
        status = EXPIRING
    else:
        status = VALID

    return ExpiryStatus(
        status=status,
        days_until_expiry=days_until,
        breach=status != VALID,
        not_after=info.not_after,
    )


def status_report(info: CertInfo, status: ExpiryStatus) -> Dict:
    """Build a JSON-serializable summary dict for one certificate."""
    return {
        "subject": info.subject,
        "common_name": info.common_name,
        "issuer": info.issuer,
        "issuer_cn": info.issuer_cn,
        "san": info.dns_names,
        "serial_number": info.serial_number,
        "not_before": info.not_before.isoformat() if info.not_before else None,
        "not_after": info.not_after.isoformat() if info.not_after else None,
        "days_until_expiry": status.days_until_expiry,
        "status": status.status,
        "breach": status.breach,
    }
