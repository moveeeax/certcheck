"""Pure certificate parsing and expiry-threshold logic.

This module performs no network or filesystem I/O. It operates on the
plain ``dict`` structure produced by :func:`ssl.SSLSocket.getpeercert`
and :func:`ssl._ssl._test_decode_cert`, so it is fully unit-testable
without a live TLS connection.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple


class CertParseError(ValueError):
    """Raised when a certificate dict cannot be understood."""


def parse_asn1_time(value: str) -> datetime:
    """Parse an OpenSSL ASN.1 time string into an aware UTC datetime.

    Example input: ``'Jun  1 12:00:00 2021 GMT'`` (note the padding
    space for single-digit days).
    """
    if not value:
        raise CertParseError("empty time value")
    text = value.strip()
    if text.endswith(" GMT") or text.endswith(" UTC"):
        text = text[:-4].strip()
    try:
        dt = datetime.strptime(text, "%b %d %H:%M:%S %Y")
    except ValueError as exc:
        raise CertParseError("bad time value: %r" % value) from exc
    return dt.replace(tzinfo=timezone.utc)


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
