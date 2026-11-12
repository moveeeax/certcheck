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
UNTRUSTED = "untrusted"
HOSTNAME_MISMATCH = "hostname_mismatch"

# OpenSSL X509_V_ERR_* verify codes (include/openssl/x509_vfy.h) that the
# trust and chain checks tell apart. ssl.SSLCertVerificationError carries
# them as ``verify_code``.
X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT = 2
X509_V_ERR_CERT_NOT_YET_VALID = 9
X509_V_ERR_CERT_HAS_EXPIRED = 10
X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT = 18
X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN = 19
X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY = 20
X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE = 21
X509_V_ERR_HOSTNAME_MISMATCH = 62
X509_V_ERR_IP_ADDRESS_MISMATCH = 64

_NAME_MISMATCH_CODES = (X509_V_ERR_HOSTNAME_MISMATCH, X509_V_ERR_IP_ADDRESS_MISMATCH)
_MISSING_ISSUER_CODES = (
    X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT,
    X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY,
    X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE,
)


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

    @property
    def self_signed(self) -> bool:
        """True when subject and issuer names are identical."""
        return bool(self.subject) and self.subject == self.issuer


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


def apply_verify_failure(status: ExpiryStatus, verify_code: Optional[int]) -> ExpiryStatus:
    """Fold a failed TLS verification into an expiry classification.

    The dates win when they already explain the failure: an expired or
    not-yet-valid certificate keeps that status. Otherwise a name
    mismatch becomes ``hostname_mismatch`` and any other trust failure
    (self-signed, unknown issuer, expired intermediate) ``untrusted``.
    The result is always a breach.
    """
    if status.status in (EXPIRED, NOT_YET_VALID):
        new_status = status.status
    elif verify_code in _NAME_MISMATCH_CODES:
        new_status = HOSTNAME_MISMATCH
    else:
        new_status = UNTRUSTED
    return ExpiryStatus(
        status=new_status,
        days_until_expiry=status.days_until_expiry,
        breach=True,
        not_after=status.not_after,
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


def chain_findings(
    chain: List[Tuple[CertInfo, ExpiryStatus]],
    verify_code: Optional[int] = None,
    verify_error: Optional[str] = None,
    check_trust: bool = True,
) -> List[Dict[str, str]]:
    """List problems with a presented chain, leaf first.

    ``chain`` pairs each presented certificate with its evaluation.
    Certificates above the leaf that are not plainly valid are reported
    as ``chain_<status>``; the leaf's own expiry is already in its
    status. With ``check_trust``, a failed verification (``verify_code``)
    is mapped to ``self_signed``, ``hostname_mismatch``,
    ``incomplete_chain`` or ``untrusted`` (described by
    ``verify_error``). A self-signed leaf that verified, for example
    against ``--ca-file``, is not a finding. Each finding is a dict with
    ``check`` and ``detail``.
    """
    findings: List[Dict[str, str]] = []
    for depth, (info, status) in enumerate(chain):
        if depth == 0 or status.status == VALID:
            continue
        findings.append({
            "check": "chain_" + status.status,
            "detail": "chain certificate %d (%s) is %s, %d days left"
            % (depth, info.common_name or "-", status.status, status.days_until_expiry),
        })

    if not check_trust or verify_code is None:
        return findings

    leaf_self_signed = bool(chain) and chain[0][0].self_signed
    if leaf_self_signed:
        findings.append({"check": "self_signed", "detail": "leaf certificate is self-signed"})
    if verify_code in _NAME_MISMATCH_CODES:
        findings.append({
            "check": "hostname_mismatch",
            "detail": "certificate does not cover the requested host name",
        })
    elif verify_code in _MISSING_ISSUER_CODES and not leaf_self_signed:
        last = chain[-1][0].common_name if chain else None
        findings.append({
            "check": "incomplete_chain",
            "detail": "issuer of %s was not presented and is not in the trust store"
            % (last or "the last presented certificate"),
        })
    elif verify_code in (X509_V_ERR_CERT_HAS_EXPIRED, X509_V_ERR_CERT_NOT_YET_VALID) and any(
        status.status in (EXPIRED, NOT_YET_VALID) for _, status in chain
    ):
        pass  # the leaf status or a chain_expired finding already says so
    elif not (leaf_self_signed and verify_code == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT):
        findings.append({
            "check": "untrusted",
            "detail": verify_error or "verification failed (code %d)" % verify_code,
        })
    return findings


# Key-exchange labels from ssl.SSLContext.get_ciphers() ("kea") that give
# forward secrecy. "kx-any" is how OpenSSL labels TLS 1.3 suites, whose key
# exchange is always ephemeral.
_FORWARD_SECRET_KEA = ("kx-ecdhe", "kx-dhe", "kx-any", "kx-ecdhepsk", "kx-dhepsk")


def forward_secret(kea: Optional[str]) -> bool:
    """Whether a cipher's key exchange (``get_ciphers()['kea']``) is ephemeral."""
    return kea in _FORWARD_SECRET_KEA


TLS_VERSIONS = ("TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3")


def protocol_findings(accepted: Dict[str, Optional[bool]], min_version: str) -> List[Dict[str, str]]:
    """Report every accepted protocol version older than ``min_version``.

    ``accepted`` maps names from :data:`TLS_VERSIONS` to True (handshake
    succeeded), False (refused) or None (could not be tested).
    """
    floor = TLS_VERSIONS.index(min_version)
    return [
        {"check": "protocol", "detail": "%s accepted, policy minimum is %s" % (name, min_version)}
        for name in TLS_VERSIONS[:floor]
        if accepted.get(name) is True
    ]
