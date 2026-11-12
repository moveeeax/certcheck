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
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from . import __version__
from .core import (
    TLS_VERSIONS,
    CertParseError,
    apply_verify_failure,
    evaluate,
    parse_cert,
    status_report,
)

EXIT_OK = 0
EXIT_BREACH = 1
EXIT_ERROR = 2

DEFAULT_PORT = 443
MIN_PORT = 1
MAX_PORT = 65535


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
        if not host:
            raise CertCheckError("missing host in %r" % target)
        if not rest:
            return host, default_port
        if rest.startswith(":"):
            return host, _parse_port(rest[1:], target)
        raise CertCheckError("unexpected text after ']' in %r" % target)

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
    if not (MIN_PORT <= port <= MAX_PORT):
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


@dataclass
class PeerCert:
    """What one TLS handshake revealed about the server's certificate.

    ``verify_code`` and ``verify_error`` are set when the verifying
    handshake failed and the certificate was read on a second,
    unverified connection. ``chain`` holds the presented certificates in
    DER form, leaf first, or None when this Python cannot expose them.
    """

    cert: Dict
    verify_code: Optional[int] = None
    verify_error: Optional[str] = None
    chain: Optional[List[bytes]] = None
    protocol: Optional[str] = None
    cipher: Optional[str] = None


def _unverified_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def verifying_context(ca_file: Optional[str] = None) -> ssl.SSLContext:
    """Default verifying context, trusting ``ca_file`` instead of the system store."""
    try:
        return ssl.create_default_context(cafile=ca_file)
    except (OSError, ssl.SSLError) as exc:
        raise CertCheckError("could not load CA file %s: %s" % (ca_file, exc))


def _presented_chain(ssock: ssl.SSLSocket) -> Optional[List[bytes]]:
    """Return the chain the peer sent, as DER, leaf first.

    ``SSLSocket.get_unverified_chain`` is public from Python 3.13. On
    3.11 and 3.12 the same data is reachable through the private
    ``_sslobj`` method that the public one wraps; if neither exists the
    chain is reported as unavailable rather than guessed.
    """
    getter = getattr(ssock, "get_unverified_chain", None)
    if getter is not None:
        return list(getter() or [])
    sslobj = getattr(ssock, "_sslobj", None)
    private = getattr(sslobj, "get_unverified_chain", None)
    if private is None:
        return None
    try:
        import _ssl  # type: ignore
        return [cert.public_bytes(_ssl.ENCODING_DER) for cert in private() or []]
    except (AttributeError, ValueError):  # pragma: no cover - depends on interpreter
        return None


def tls_handshake(host: str, port: int, timeout: float, context: ssl.SSLContext) -> PeerCert:
    """Connect with ``context`` and read the peer certificate and chain.

    A verification failure propagates as
    :class:`ssl.SSLCertVerificationError`; every other failure becomes a
    :class:`CertCheckError`.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    der = ssock.getpeercert(binary_form=True)
                    if der:
                        cert = _decode_der(der)
                cipher = ssock.cipher()
                return PeerCert(
                    cert=cert or {},
                    chain=_presented_chain(ssock),
                    protocol=ssock.version(),
                    cipher=cipher[0] if cipher else None,
                )
    except ssl.SSLCertVerificationError:
        raise
    except ssl.SSLError as exc:
        raise CertCheckError("TLS error for %s:%s: %s" % (host, port, exc))
    except socket.timeout:
        raise CertCheckError("timed out connecting to %s:%s" % (host, port))
    except OSError as exc:
        raise CertCheckError("could not connect to %s:%s: %s" % (host, port, exc))


def fetch_peer(host: str, port: int, timeout: float, insecure: bool = False,
               ca_file: Optional[str] = None) -> PeerCert:
    """Read the peer certificate, recording why verification failed.

    Without ``insecure`` the first handshake verifies the chain and the
    host name. If that fails, the certificate is read again over an
    unverified connection so an expired, self-signed or wrong-host
    certificate is still reported, with ``verify_code`` and
    ``verify_error`` set. With ``insecure`` only the unverified
    handshake runs and trust is not judged at all. ``ca_file`` replaces
    the system trust store for the verifying handshake.
    """
    if insecure:
        return tls_handshake(host, port, timeout, _unverified_context())
    context = verifying_context(ca_file)
    try:
        return tls_handshake(host, port, timeout, context)
    except ssl.SSLCertVerificationError as exc:
        peer = tls_handshake(host, port, timeout, _unverified_context())
        peer.verify_code = exc.verify_code
        peer.verify_error = exc.verify_message or str(exc)
        return peer


def fetch_cert(host: str, port: int, timeout: float, insecure: bool = False,
               ca_file: Optional[str] = None) -> Dict:
    """Return only the peer certificate dict (see :func:`fetch_peer`)."""
    return fetch_peer(host, port, timeout, insecure, ca_file).cert


def _one_target_report(label: str, raw_cert: Dict, warn_days: int,
                       peer: Optional[PeerCert] = None) -> Dict:
    info = parse_cert(raw_cert)
    status = evaluate(info, warn_days=warn_days)
    if peer is not None and peer.verify_error is not None:
        status = apply_verify_failure(status, peer.verify_code)
    report = status_report(info, status)
    report["target"] = label
    if peer is not None and peer.verify_error is not None:
        report["verify_error"] = peer.verify_error
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
    if report.get("verify_error"):
        lines.append("Verify:      %s" % report["verify_error"])
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
            report = _one_target_report(args.file, raw, args.warn_days)
        else:
            if not args.target:
                raise CertCheckError("a HOST[:PORT] or --file is required")
            host, port = parse_target(args.target, args.port)
            peer = fetch_peer(host, port, args.timeout, args.insecure, args.ca_file)
            report = _one_target_report("%s:%s" % (host, port), peer.cert,
                                        args.warn_days, peer)
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
    # utf-8-sig so a byte-order mark left by a Windows editor does not
    # end up glued to the first hostname; without an explicit encoding
    # the read would also follow the ambient locale.
    with open(path, "r", encoding="utf-8-sig") as handle:
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
            peer = fetch_peer(host, port, args.timeout, args.insecure, args.ca_file)
            report = _one_target_report("%s:%s" % (host, port), peer.cert,
                                        args.warn_days, peer)
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


def cmd_inventory(args: argparse.Namespace) -> int:
    # Imported here: certcheck.inventory builds on the helpers in this module.
    from .inventory import format_inventory, run_inventory

    try:
        hosts = _read_host_lines(args.file)
    except CertCheckError as exc:
        _emit_error(str(exc), args.json)
        return EXIT_ERROR

    reports = run_inventory(hosts, args)
    if args.json:
        print(json.dumps(reports, indent=2, sort_keys=True))
    elif reports:
        print(format_inventory(reports))
    return EXIT_BREACH if any(r["breach"] for r in reports) else EXIT_OK


def cmd_k8s(args: argparse.Namespace) -> int:
    from .k8s import build_rows, fetch_objects, format_rows, kubectl_runner

    global_args: List[str] = []
    if args.kubeconfig:
        global_args += ["--kubeconfig", args.kubeconfig]
    if args.context:
        global_args += ["--context", args.context]
    run = kubectl_runner(args.kubectl, args.timeout, global_args)
    try:
        objects = fetch_objects(run, args.namespace, args.all_namespaces, args.selector)
    except CertCheckError as exc:
        _emit_error(str(exc), args.json)
        return EXIT_ERROR

    rows = build_rows(
        objects["secrets"], objects["certificates"], args.warn_days,
        exclude_namespaces=args.exclude_namespace or (),
        exclude_issuers=args.exclude_issuer or (),
        include_orphans=not args.selector,
    )
    if args.json:
        print(json.dumps(rows, indent=2, sort_keys=True))
    else:
        print(format_rows(rows))
    return EXIT_BREACH if any(r["breach"] for r in rows) else EXIT_OK


def _min_version(text: str) -> str:
    names = {v.lower().replace("v", ""): v for v in TLS_VERSIONS}
    key = text.lower().replace("v", "")
    if key not in names:
        raise argparse.ArgumentTypeError(
            "expected one of %s" % ", ".join(sorted(names))
        )
    return names[key]


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
                        help="skip certificate verification; trust failures are not reported")
        sp.add_argument("--ca-file", metavar="PATH",
                        help="verify against this PEM CA bundle instead of the system store")

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

    p_inv = sub.add_parser(
        "inventory",
        help="survey chain, protocol versions and ciphers of many hosts",
    )
    p_inv.add_argument("--file", required=True,
                       help="file with one HOST[:PORT] per line")
    add_common(p_inv)
    p_inv.add_argument("--min-version", type=_min_version, default="TLSv1.2",
                       metavar="VERSION",
                       help="flag hosts accepting older TLS: tls1.0, tls1.1, tls1.2 "
                            "or tls1.3 (default tls1.2)")
    p_inv.add_argument("--ciphers", action="store_true",
                       help="also list accepted cipher suites (one handshake per suite)")
    p_inv.add_argument("--require-forward-secrecy", action="store_true",
                       help="with --ciphers, flag suites without forward secrecy")
    p_inv.add_argument("--concurrency", type=int, default=10,
                       help="hosts surveyed in parallel (default 10)")
    p_inv.set_defaults(func=cmd_inventory)

    p_k8s = sub.add_parser(
        "k8s",
        help="check TLS secrets and cert-manager Certificates via kubectl",
    )
    p_k8s.add_argument("-n", "--namespace", help="namespace (default: kubectl's current one)")
    p_k8s.add_argument("-A", "--all-namespaces", action="store_true",
                       help="check every namespace")
    p_k8s.add_argument("-l", "--selector", help="label selector for TLS secrets")
    p_k8s.add_argument("--exclude-namespace", action="append", metavar="GLOB",
                       help="skip namespaces matching GLOB (repeatable)")
    p_k8s.add_argument("--exclude-issuer", action="append", metavar="GLOB",
                       help="skip certs whose issuer CN or cert-manager issuer name "
                            "matches GLOB (repeatable)")
    p_k8s.add_argument("--context", help="kubeconfig context to use")
    p_k8s.add_argument("--kubeconfig", help="path to the kubeconfig file")
    p_k8s.add_argument("--kubectl", default="kubectl",
                       help="kubectl binary (default: kubectl on PATH)")
    p_k8s.add_argument("--warn-days", type=int, default=30,
                       help="warn/fail if a cert expires within this many days (default 30)")
    p_k8s.add_argument("--timeout", type=float, default=10.0,
                       help="kubectl request timeout in seconds (default 10)")
    p_k8s.add_argument("--json", action="store_true", help="emit JSON output")
    p_k8s.set_defaults(func=cmd_k8s)

    return parser


def validate_common_args(args: argparse.Namespace) -> Optional[str]:
    """Return an error message for out-of-range shared options, else None.

    ``--timeout`` and ``--port`` are checked here because passing them
    straight to :func:`socket.create_connection` turns bad input into an
    unhandled traceback (a non-positive timeout raises ``ValueError``)
    or a misleading DNS error (an out-of-range port), instead of the
    clear message and exit code 2 the CLI promises.
    """
    if args.warn_days < 0:
        return "--warn-days must be non-negative"
    if not args.timeout > 0:
        return "--timeout must be greater than 0"
    port = getattr(args, "port", DEFAULT_PORT)
    if not (MIN_PORT <= port <= MAX_PORT):
        return "--port must be between %d and %d" % (MIN_PORT, MAX_PORT)
    if getattr(args, "concurrency", 1) < 1:
        return "--concurrency must be at least 1"
    if getattr(args, "require_forward_secrecy", False) and not args.ciphers:
        return "--require-forward-secrecy needs --ciphers"
    if getattr(args, "namespace", None) and getattr(args, "all_namespaces", False):
        return "--namespace and --all-namespaces are mutually exclusive"
    return None


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help(sys.stderr)
        return EXIT_ERROR
    problem = validate_common_args(args)
    if problem is not None:
        _emit_error(problem, getattr(args, "json", False))
        return EXIT_ERROR
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
