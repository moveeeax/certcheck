"""Command-line interface: argument parsing, network/file I/O, dispatch.

All the impure work lives here. Pure classification logic is in
:mod:`certcheck.core`.
"""

import argparse
import json
import os
import socket
import ssl
import sys
import tempfile
from typing import Dict, List, Optional, Tuple

from . import __version__
from .core import (
    CertParseError,
    evaluate,
    parse_cert,
    status_report,
)

EXIT_OK = 0
EXIT_BREACH = 1
EXIT_ERROR = 2

DEFAULT_PORT = 443


class CertCheckError(Exception):
    """User-facing error (bad host, connection failure, unreadable file)."""


def parse_target(target: str, default_port: int = DEFAULT_PORT) -> Tuple[str, int]:
    """Split ``HOST[:PORT]`` into a ``(host, port)`` pair.

    Supports bare hostnames, IPv4 ``host:port``, and bracketed IPv6
    ``[::1]:443``. Bare IPv6 (multiple colons, no brackets) is treated
    as a host with the default port.
    """
    text = target.strip()
    if not text:
        raise CertCheckError("empty host")

    if text.startswith("["):
        host, sep, rest = text[1:].partition("]")
        if not sep:
            raise CertCheckError("unbalanced brackets in %r" % target)
        if rest.startswith(":"):
            return host, _parse_port(rest[1:], target)
        return host, default_port

    if text.count(":") == 1:
        host, _, port_text = text.partition(":")
        if not host:
            raise CertCheckError("missing host in %r" % target)
        return host, _parse_port(port_text, target)

    return text, default_port


def _parse_port(port_text: str, original: str) -> int:
    try:
        port = int(port_text)
    except ValueError:
        raise CertCheckError("invalid port in %r" % original)
    if not (0 < port < 65536):
        raise CertCheckError("port out of range in %r" % original)
    return port


def decode_cert_file(path: str) -> Dict:
    """Decode a PEM certificate file into a getpeercert-style dict.

    Uses the stdlib ``_ssl._test_decode_cert`` helper so no third-party
    dependency is needed.
    """
    if not os.path.exists(path):
        raise CertCheckError("no such file: %s" % path)
    try:
        import _ssl  # type: ignore
    except ImportError:  # pragma: no cover - _ssl is always present with ssl
        raise CertCheckError("stdlib _ssl module unavailable")
    try:
        return _ssl._test_decode_cert(path)
    except Exception as exc:  # noqa: BLE001 - surface any decode failure
        raise CertCheckError("could not parse certificate %s: %s" % (path, exc))


def _decode_der(der: bytes) -> Dict:
    pem = ssl.DER_cert_to_PEM_cert(der)
    handle = tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False)
    try:
        handle.write(pem)
        handle.close()
        return decode_cert_file(handle.name)
    finally:
        os.unlink(handle.name)


def fetch_cert(host: str, port: int, timeout: float, insecure: bool = False) -> Dict:
    """Open a TLS connection and return the peer certificate dict.

    When ``insecure`` is set, verification is disabled but the peer
    certificate is still read (via its DER form) so self-signed certs
    can be inspected.
    """
    context = ssl.create_default_context()
    if insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    der = ssock.getpeercert(binary_form=True)
                    if der:
                        cert = _decode_der(der)
                return cert or {}
    except ssl.SSLError as exc:
        raise CertCheckError("TLS error for %s:%s: %s" % (host, port, exc))
    except socket.timeout:
        raise CertCheckError("timed out connecting to %s:%s" % (host, port))
    except OSError as exc:
        raise CertCheckError("could not connect to %s:%s: %s" % (host, port, exc))


def _one_target_report(label: str, raw_cert: Dict, warn_days: int) -> Dict:
    info = parse_cert(raw_cert)
    status = evaluate(info, warn_days=warn_days)
    report = status_report(info, status)
    report["target"] = label
    return report


def format_human(report: Dict) -> str:
    lines = [
        "Target:      %s" % report.get("target", "-"),
        "Subject CN:  %s" % (report.get("common_name") or "-"),
        "Issuer CN:   %s" % (report.get("issuer_cn") or "-"),
        "SAN:         %s" % (", ".join(report.get("san") or []) or "-"),
        "Not before:  %s" % (report.get("not_before") or "-"),
        "Not after:   %s" % (report.get("not_after") or "-"),
        "Days left:   %s" % report.get("days_until_expiry"),
        "Status:      %s" % report.get("status"),
    ]
    return "\n".join(lines)


def _emit_error(message: str, as_json: bool) -> None:
    if as_json:
        print(json.dumps({"error": message}), file=sys.stderr)
    else:
        print("error: %s" % message, file=sys.stderr)


def cmd_check(args: argparse.Namespace) -> int:
    try:
        if args.file:
            raw = decode_cert_file(args.file)
            label = args.file
        else:
            if not args.target:
                raise CertCheckError("a HOST[:PORT] or --file is required")
            host, port = parse_target(args.target, args.port)
            raw = fetch_cert(host, port, args.timeout, args.insecure)
            label = "%s:%s" % (host, port)
        report = _one_target_report(label, raw, args.warn_days)
    except (CertCheckError, CertParseError) as exc:
        _emit_error(str(exc), args.json)
        return EXIT_ERROR

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(format_human(report))
    return EXIT_BREACH if report["breach"] else EXIT_OK


def _read_host_lines(path: str) -> List[str]:
    if not os.path.exists(path):
        raise CertCheckError("no such file: %s" % path)
    hosts = []
    with open(path, "r") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            hosts.append(line)
    return hosts


def cmd_batch(args: argparse.Namespace) -> int:
    try:
        hosts = _read_host_lines(args.file)
    except CertCheckError as exc:
        _emit_error(str(exc), args.json)
        return EXIT_ERROR

    reports: List[Dict] = []
    any_breach = False
    any_error = False

    for entry in hosts:
        try:
            host, port = parse_target(entry, args.port)
            raw = fetch_cert(host, port, args.timeout, args.insecure)
            report = _one_target_report("%s:%s" % (host, port), raw, args.warn_days)
        except (CertCheckError, CertParseError) as exc:
            any_error = True
            reports.append(
                {"target": entry, "status": "error", "error": str(exc), "breach": True}
            )
            continue
        any_breach = any_breach or report["breach"]
        reports.append(report)

    if args.json:
        print(json.dumps(reports, indent=2, sort_keys=True))
    else:
        for report in reports:
            if report.get("status") == "error":
                print("%s  ERROR  %s" % (report["target"], report.get("error")))
            else:
                print(
                    "%s  %s  %s days"
                    % (report["target"], report["status"].upper(),
                       report["days_until_expiry"])
                )

    if any_error or any_breach:
        return EXIT_BREACH
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="certcheck",
        description="Inspect TLS certificate expiry and details.",
    )
    parser.add_argument("--version", action="version",
                        version="certcheck %s" % __version__)
    sub = parser.add_subparsers(dest="command")

    def add_common(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--warn-days", type=int, default=30,
                        help="warn/fail if a cert expires within this many days (default 30)")
        sp.add_argument("--timeout", type=float, default=10.0,
                        help="connection timeout in seconds (default 10)")
        sp.add_argument("--port", type=int, default=DEFAULT_PORT,
                        help="default port when none given (default 443)")
        sp.add_argument("--json", action="store_true", help="emit JSON output")
        sp.add_argument("--insecure", action="store_true",
                        help="skip certificate verification but still read the cert")

    p_check = sub.add_parser("check", help="check a single host or PEM file")
    p_check.add_argument("target", nargs="?", help="HOST[:PORT] to connect to")
    p_check.add_argument("--file", help="inspect a local PEM file instead of connecting")
    add_common(p_check)
    p_check.set_defaults(func=cmd_check)

    p_batch = sub.add_parser("batch", help="check many hosts listed in a file")
    p_batch.add_argument("--file", required=True,
                         help="file with one HOST[:PORT] per line")
    add_common(p_batch)
    p_batch.set_defaults(func=cmd_batch)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help(sys.stderr)
        return EXIT_ERROR
    if args.warn_days < 0:
        _emit_error("--warn-days must be non-negative", getattr(args, "json", False))
        return EXIT_ERROR
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
