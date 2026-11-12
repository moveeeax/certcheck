"""``certcheck inventory``: chain, protocol and cipher survey of many hosts.

Each host gets the leaf check that ``check`` does, plus the presented
chain, one handshake per TLS version, and optionally one handshake per
TLS 1.2-and-older cipher suite. Classification lives in
:mod:`certcheck.core`; this module only does the handshakes.
"""

import ssl
import warnings
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional

from .cli import (
    CertCheckError,
    _decode_der,
    _one_target_report,
    _unverified_context,
    fetch_peer,
    parse_target,
    tls_handshake,
)
from .core import (
    TLS_VERSIONS,
    CertParseError,
    chain_findings,
    evaluate,
    forward_secret,
    parse_cert,
    protocol_findings,
)

# ssl.HAS_TLSv1_2 and friends are not consulted: they track whether the
# version-specific OpenSSL methods were compiled in, which newer OpenSSL
# builds report as False while still negotiating the version. A context
# that cannot offer a version fails with NO_PROTOCOLS_AVAILABLE instead.
_TLS_VERSION_ENUM = {
    "TLSv1.0": "TLSv1",
    "TLSv1.1": "TLSv1_1",
    "TLSv1.2": "TLSv1_2",
    "TLSv1.3": "TLSv1_3",
}

# Probe contexts drop OpenSSL's security level so that this client does
# not refuse an old protocol or weak suite on its own; the point is to
# learn what the server accepts.
_PROBE_CIPHERS = "ALL:COMPLEMENTOFALL:@SECLEVEL=0"

# OpenSSL error reasons that mean the client could not offer what was
# asked, as opposed to the server refusing it.
_CLIENT_SIDE_REASONS = ("NO_PROTOCOLS_AVAILABLE", "NO_CIPHERS_AVAILABLE", "NO_CIPHER_MATCH")


def _probe_context(version: str, ciphers: str = _PROBE_CIPHERS) -> Optional[ssl.SSLContext]:
    """An unverified context pinned to one TLS version, or None if unsupported here."""
    enum_name = _TLS_VERSION_ENUM[version]
    context = _unverified_context()
    try:
        with warnings.catch_warnings():
            # TLSVersion.TLSv1 and TLSv1_1 are deprecated; probing them is the point.
            warnings.simplefilter("ignore", DeprecationWarning)
            tls_version = getattr(ssl.TLSVersion, enum_name)
            context.minimum_version = tls_version
            context.maximum_version = tls_version
        context.set_ciphers(ciphers)
    except (ValueError, ssl.SSLError):
        return None
    return context


def _accepts(host: str, port: int, timeout: float,
             context: Optional[ssl.SSLContext], version: str) -> Optional[bool]:
    """True if a ``version`` handshake succeeds, False if refused, None if untestable."""
    if context is None:
        return None
    try:
        peer = tls_handshake(host, port, timeout, context)
    except CertCheckError as exc:
        # tls_handshake wraps the underlying error; it stays on __context__.
        cause = exc.__context__
        if isinstance(cause, ssl.SSLError):
            if cause.reason in _CLIENT_SIDE_REASONS:
                return None
            return False
        if isinstance(cause, ConnectionResetError):
            # Some servers drop the connection instead of sending an alert.
            return False
        return None
    # Pinned min and max should make any other outcome impossible; the
    # check keeps a misbehaving build from reporting the wrong version.
    # SSLSocket.version() calls TLS 1.0 "TLSv1".
    negotiated = {"TLSv1": "TLSv1.0"}.get(peer.protocol, peer.protocol)
    return negotiated == version


def probe_protocols(host: str, port: int, timeout: float) -> Dict[str, Optional[bool]]:
    """Try one handshake per TLS version and report which the server accepts."""
    return {
        version: _accepts(host, port, timeout, _probe_context(version), version)
        for version in TLS_VERSIONS
    }


def _legacy_suites() -> List[Dict]:
    """TLS 1.2-and-older suites this client's OpenSSL can offer."""
    context = _unverified_context()
    try:
        context.set_ciphers(_PROBE_CIPHERS)
    except ssl.SSLError:  # pragma: no cover - depends on the OpenSSL build
        return []
    return [c for c in context.get_ciphers() if c.get("protocol") != "TLSv1.3"]


def probe_ciphers(host: str, port: int, timeout: float,
                  protocols: Dict[str, Optional[bool]]) -> List[Dict]:
    """List the cipher suites the server accepts, each with a forward-secrecy flag.

    TLS 1.2-and-older suites are tried one at a time on the newest of
    those versions the server accepted. Python cannot restrict TLS 1.3
    suites, so for TLS 1.3 only the suite the server picks is listed.
    """
    accepted: List[Dict] = []
    legacy = [v for v in ("TLSv1.2", "TLSv1.1", "TLSv1.0") if protocols.get(v)]
    if legacy:
        version = legacy[0]
        for suite in _legacy_suites():
            context = _probe_context(version, suite["name"] + ":@SECLEVEL=0")
            if _accepts(host, port, timeout, context, version):
                accepted.append({
                    "name": suite["name"],
                    "protocol": version,
                    "forward_secrecy": forward_secret(suite.get("kea")),
                })
    if protocols.get("TLSv1.3"):
        context = _probe_context("TLSv1.3")
        try:
            peer = tls_handshake(host, port, timeout, context) if context else None
        except CertCheckError:
            peer = None
        if peer is not None and peer.cipher:
            accepted.append({"name": peer.cipher, "protocol": "TLSv1.3", "forward_secrecy": True})
    return accepted


def _chain_report(chain: List[bytes], warn_days: int) -> List[Dict]:
    out = []
    for der in chain:
        info = parse_cert(_decode_der(der))
        status = evaluate(info, warn_days=warn_days)
        out.append((info, status))
    return out


def inventory_host(entry: str, args) -> Dict:
    """Survey one ``HOST[:PORT]`` entry; never raises for per-host failures."""
    try:
        host, port = parse_target(entry, args.port)
        label = "%s:%s" % (host, port)
        peer = fetch_peer(host, port, args.timeout, args.insecure, args.ca_file)
        report = _one_target_report(label, peer.cert, args.warn_days, peer)

        evaluated = _chain_report(peer.chain, args.warn_days) if peer.chain else []
        report["chain"] = None if peer.chain is None else [
            {
                "common_name": info.common_name,
                "issuer_cn": info.issuer_cn,
                "not_after": info.not_after.isoformat() if info.not_after else None,
                "days_until_expiry": status.days_until_expiry,
                "status": status.status,
                "self_signed": info.self_signed,
            }
            for info, status in evaluated
        ]
        if not evaluated:
            leaf = parse_cert(peer.cert)
            evaluated = [(leaf, evaluate(leaf, warn_days=args.warn_days))]
        findings = chain_findings(evaluated, peer.verify_code, peer.verify_error,
                                  check_trust=not args.insecure)

        protocols = probe_protocols(host, port, args.timeout)
        report["protocols"] = protocols
        findings += protocol_findings(protocols, args.min_version)

        if args.ciphers:
            ciphers = probe_ciphers(host, port, args.timeout, protocols)
            report["ciphers"] = ciphers
            if args.require_forward_secrecy:
                findings += [
                    {"check": "forward_secrecy",
                     "detail": "%s (%s) has no forward secrecy" % (c["name"], c["protocol"])}
                    for c in ciphers if not c["forward_secrecy"]
                ]
    except (CertCheckError, CertParseError) as exc:
        return {"target": entry, "status": "error", "error": str(exc), "breach": True,
                "findings": []}

    report["findings"] = findings
    report["breach"] = report["breach"] or bool(findings)
    return report


def run_inventory(hosts: List[str], args) -> List[Dict]:
    """Survey ``hosts`` with up to ``args.concurrency`` in flight, keeping input order."""
    with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        return list(pool.map(lambda entry: inventory_host(entry, args), hosts))


def format_inventory(reports: List[Dict]) -> str:
    lines = []
    for report in reports:
        if report.get("status") == "error":
            lines.append("%s  ERROR  %s" % (report["target"], report.get("error")))
            continue
        offered = [v for v, ok in (report.get("protocols") or {}).items() if ok]
        lines.append("%s  %s  %s days  issuer=%s  protocols=%s" % (
            report["target"], report["status"].upper(), report["days_until_expiry"],
            report.get("issuer_cn") or "-", ",".join(offered) or "-",
        ))
        for finding in report.get("findings") or []:
            lines.append("  ! %s: %s" % (finding["check"], finding["detail"]))
        for cipher in report.get("ciphers") or []:
            lines.append("  cipher %s %s%s" % (
                cipher["protocol"], cipher["name"],
                "" if cipher["forward_secrecy"] else "  (no forward secrecy)",
            ))
    return "\n".join(lines)
