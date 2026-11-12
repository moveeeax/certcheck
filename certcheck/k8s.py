"""``certcheck k8s``: expiry of TLS secrets and cert-manager Certificates.

Cluster access goes through the ``kubectl`` binary, so certcheck keeps
no Python dependencies and uses whatever kubeconfig, context and
credentials kubectl is already set up with. Only read verbs are used:
``get secrets``, ``get certificates`` and ``api-resources``.
"""

import base64
import binascii
import json
import re
import ssl
import subprocess
from datetime import datetime, timezone
from fnmatch import fnmatch
from typing import Callable, Dict, List, Optional, Sequence

from .cli import CertCheckError, _decode_der
from .core import VALID, CertParseError, evaluate, parse_cert, status_report

NOT_READY = "not_ready"
ERROR = "error"

CERT_MANAGER_RESOURCE = "certificates.cert-manager.io"

_PEM_BLOCK = re.compile(
    r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", re.DOTALL
)

Runner = Callable[[List[str]], str]


def kubectl_runner(kubectl: str = "kubectl", timeout: float = 10.0,
                   global_args: Sequence[str] = ()) -> Runner:
    """Return a function that runs ``kubectl <global_args> <args>`` and returns stdout."""

    def run(args: List[str]) -> str:
        cmd = [kubectl, *global_args, "--request-timeout=%gs" % timeout, *args]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        except FileNotFoundError:
            raise CertCheckError("kubectl not found; install it or pass --kubectl PATH")
        if proc.returncode != 0:
            detail = proc.stderr.strip() or "exit status %d" % proc.returncode
            raise CertCheckError("kubectl %s failed: %s" % (" ".join(args), detail))
        return proc.stdout

    return run


def _get_items(run: Runner, args: List[str]) -> List[Dict]:
    out = run(args)
    try:
        return json.loads(out).get("items") or []
    except (ValueError, AttributeError):
        raise CertCheckError("kubectl %s returned invalid JSON" % " ".join(args))


def fetch_objects(run: Runner, namespace: Optional[str], all_namespaces: bool,
                  selector: Optional[str]) -> Dict[str, List[Dict]]:
    """Fetch TLS secrets and, if cert-manager is installed, Certificates.

    ``selector`` filters secrets only: a Certificate's labels need not
    match its secret's, so Certificates are always listed in full and
    matched to secrets by ``spec.secretName``.
    """
    scope = ["--all-namespaces"] if all_namespaces else (
        ["--namespace", namespace] if namespace else []
    )
    secret_scope = scope + (["--selector", selector] if selector else [])

    secrets = _get_items(run, ["get", "secrets", "--field-selector",
                               "type=kubernetes.io/tls", "-o", "json", *secret_scope])

    resources = run(["api-resources", "--api-group=cert-manager.io", "-o", "name"]).split()
    certificates: List[Dict] = []
    if CERT_MANAGER_RESOURCE in resources:
        certificates = _get_items(run, ["get", CERT_MANAGER_RESOURCE, "-o", "json", *scope])
    return {"secrets": secrets, "certificates": certificates,
            "cert_manager": CERT_MANAGER_RESOURCE in resources}


def decode_tls_crt(value: str) -> Dict:
    """Decode the leaf (first) certificate from a base64 ``tls.crt`` value."""
    try:
        pem = base64.b64decode(value, validate=True).decode("ascii")
    except (binascii.Error, ValueError):
        raise CertCheckError("tls.crt is not valid base64 PEM")
    match = _PEM_BLOCK.search(pem)
    if not match:
        raise CertCheckError("tls.crt holds no PEM certificate")
    try:
        der = ssl.PEM_cert_to_DER_cert(match.group(0))
    except ValueError as exc:
        raise CertCheckError("tls.crt is not a valid certificate: %s" % exc)
    return _decode_der(der)


def _parse_time(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def certificate_summary(cert: Dict) -> Dict:
    """Pick the cert-manager Certificate fields the report needs."""
    meta = cert.get("metadata") or {}
    spec = cert.get("spec") or {}
    status = cert.get("status") or {}
    ready = None
    reason = message = None
    for condition in status.get("conditions") or []:
        if condition.get("type") == "Ready":
            ready = condition.get("status") == "True"
            reason = condition.get("reason")
            message = condition.get("message")
    issuer_ref = spec.get("issuerRef") or {}
    return {
        "name": meta.get("name"),
        "namespace": meta.get("namespace"),
        "secret_name": spec.get("secretName"),
        "issuer_ref": "%s/%s" % (issuer_ref.get("kind") or "Issuer", issuer_ref.get("name")),
        "issuer_name": issuer_ref.get("name"),
        "ready": ready,
        "ready_reason": reason,
        "ready_message": message,
        "not_after": status.get("notAfter"),
        "renewal_time": status.get("renewalTime"),
    }


def _excluded(namespace: Optional[str], issuers: Sequence[Optional[str]],
              exclude_namespaces: Sequence[str], exclude_issuers: Sequence[str]) -> bool:
    if namespace and any(fnmatch(namespace, pat) for pat in exclude_namespaces):
        return True
    return any(name and fnmatch(name, pat) for name in issuers for pat in exclude_issuers)


def build_rows(secrets: List[Dict], certificates: List[Dict], warn_days: int,
               now: Optional[datetime] = None,
               exclude_namespaces: Sequence[str] = (),
               exclude_issuers: Sequence[str] = (),
               include_orphans: bool = True,
               decode: Callable[[str], Dict] = decode_tls_crt) -> List[Dict]:
    """Turn kubectl items into report rows, most urgent first.

    Every TLS secret becomes a row from its leaf certificate. A
    Certificate that names the secret is attached under ``certificate``;
    if it is not Ready the row is a breach with status ``not_ready``
    unless the dates already make it expired or expiring. A Certificate
    whose secret does not exist gets a row of its own when
    ``include_orphans`` is set (it is not when secrets were filtered by
    a label selector, since the secret may just be filtered out). Rows without
    a usable expiry come first, then ascending days left.
    """
    if now is None:
        now = datetime.now(timezone.utc)
    by_secret = {}
    for cert in certificates:
        summary = certificate_summary(cert)
        by_secret[(summary["namespace"], summary["secret_name"])] = summary

    rows: List[Dict] = []
    seen = set()
    for secret in secrets:
        meta = secret.get("metadata") or {}
        namespace, name = meta.get("namespace"), meta.get("name")
        seen.add((namespace, name))
        managed = by_secret.get((namespace, name))
        target = "%s/%s" % (namespace, name)
        try:
            info = parse_cert(decode((secret.get("data") or {}).get("tls.crt") or ""))
        except (CertCheckError, CertParseError) as exc:
            if _excluded(namespace, [managed and managed["issuer_name"]],
                         exclude_namespaces, exclude_issuers):
                continue
            rows.append({"kind": "Secret", "namespace": namespace, "name": name,
                         "target": target, "status": ERROR, "error": str(exc),
                         "breach": True, "days_until_expiry": None,
                         "certificate": managed})
            continue
        if _excluded(namespace, [info.issuer_cn, managed and managed["issuer_name"]],
                     exclude_namespaces, exclude_issuers):
            continue
        status = evaluate(info, warn_days=warn_days, now=now)
        row = status_report(info, status)
        if managed is not None and managed["ready"] is False and row["status"] == VALID:
            row["status"] = NOT_READY
            row["breach"] = True
        row.update({"kind": "Secret", "namespace": namespace, "name": name,
                    "target": target, "certificate": managed})
        rows.append(row)

    for summary in by_secret.values() if include_orphans else ():
        key = (summary["namespace"], summary["secret_name"])
        if key in seen:
            continue
        if _excluded(summary["namespace"], [summary["issuer_name"]],
                     exclude_namespaces, exclude_issuers):
            continue
        not_after = _parse_time(summary["not_after"])
        days = (not_after - now).days if not_after else None
        rows.append({"kind": "Certificate", "namespace": summary["namespace"],
                     "name": summary["name"],
                     "target": "%s/%s" % (summary["namespace"], summary["name"]),
                     "status": NOT_READY if summary["ready"] is not True else ERROR,
                     "error": "secret %s does not exist" % summary["secret_name"],
                     "breach": True, "days_until_expiry": days,
                     "not_after": summary["not_after"], "certificate": summary})

    rows.sort(key=lambda r: (r.get("days_until_expiry") is not None,
                             r.get("days_until_expiry") or 0, r["target"]))
    return rows


def format_rows(rows: List[Dict]) -> str:
    """Render rows as an aligned table."""
    header = ("DAYS", "STATUS", "KIND", "NAMESPACE/NAME", "SUBJECT", "ISSUER", "NOTE")
    table = [header]
    for row in rows:
        cert = row.get("certificate") or {}
        if row.get("error"):
            note = row["error"]
        elif cert.get("ready") is False:
            note = "not Ready: %s" % (cert.get("ready_reason") or "-")
        elif cert.get("renewal_time"):
            note = "renews %s" % cert["renewal_time"]
        else:
            note = ""
        days = row.get("days_until_expiry")
        table.append((
            "-" if days is None else str(days),
            row["status"],
            row["kind"],
            row["target"],
            row.get("common_name") or "-",
            row.get("issuer_cn") or (cert.get("issuer_ref") if cert else None) or "-",
            note,
        ))
    widths = [max(len(line[i]) for line in table) for i in range(len(header))]
    return "\n".join(
        "  ".join(cell.ljust(width) for cell, width in zip(line, widths)).rstrip()
        for line in table
    )
