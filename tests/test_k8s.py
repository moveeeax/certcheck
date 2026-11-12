import base64
import json
import os
import stat
import sys
from datetime import datetime, timedelta, timezone

import pytest

from certcheck import k8s
from certcheck.cli import EXIT_BREACH, EXIT_ERROR, EXIT_OK, CertCheckError, main
from tests.conftest import make_cert_dict, write_self_signed

NOW = datetime(2021, 6, 1, 12, 0, 0, tzinfo=timezone.utc)


def _cert(days_from_now, cn="app.example.test", issuer_cn="Let's Encrypt R3"):
    not_after = NOW + timedelta(days=days_from_now)
    return make_cert_dict(not_after - timedelta(days=90), not_after,
                          cn=cn, issuer_cn=issuer_cn)


def _secret(namespace, name, tls_crt):
    return {"metadata": {"namespace": namespace, "name": name},
            "type": "kubernetes.io/tls", "data": {"tls.crt": tls_crt, "tls.key": "eA=="}}


def _certificate(namespace, name, secret_name, ready="True", reason="Ready",
                 issuer="letsencrypt", renewal="2021-06-20T00:00:00Z",
                 not_after="2021-07-01T00:00:00Z"):
    return {
        "metadata": {"namespace": namespace, "name": name},
        "spec": {"secretName": secret_name,
                 "issuerRef": {"name": issuer, "kind": "ClusterIssuer"}},
        "status": {
            "conditions": [{"type": "Ready", "status": ready, "reason": reason,
                            "message": "msg"}],
            "notAfter": not_after,
            "renewalTime": renewal,
        },
    }


def _rows(secrets, certificates=(), certs_by_key=None, **kwargs):
    """build_rows with tls.crt values used as keys into ``certs_by_key``."""
    certs_by_key = certs_by_key or {}

    def decode(value):
        if value not in certs_by_key:
            raise CertCheckError("tls.crt holds no PEM certificate")
        return certs_by_key[value]

    return k8s.build_rows(secrets, list(certificates), warn_days=30, now=NOW,
                          decode=decode, **kwargs)


def test_rows_sorted_by_days_left():
    rows = _rows(
        [_secret("a", "later", "c1"), _secret("b", "soon", "c2"), _secret("c", "ok", "c3")],
        certs_by_key={"c1": _cert(60), "c2": _cert(3), "c3": _cert(45)},
    )
    assert [r["target"] for r in rows] == ["b/soon", "c/ok", "a/later"]
    assert [r["status"] for r in rows] == ["expiring", "valid", "valid"]
    assert rows[0]["breach"] is True
    assert rows[0]["common_name"] == "app.example.test"
    assert rows[0]["issuer_cn"] == "Let's Encrypt R3"
    assert rows[0]["san"] == ["example.test", "www.example.test"]


def test_cert_manager_details_are_attached():
    rows = _rows([_secret("web", "tls", "c1")],
                 [_certificate("web", "site", "tls")],
                 certs_by_key={"c1": _cert(60)})
    cert = rows[0]["certificate"]
    assert cert["name"] == "site"
    assert cert["ready"] is True
    assert cert["renewal_time"] == "2021-06-20T00:00:00Z"
    assert cert["issuer_ref"] == "ClusterIssuer/letsencrypt"
    assert rows[0]["status"] == "valid"


def test_not_ready_certificate_breaches():
    rows = _rows([_secret("web", "tls", "c1")],
                 [_certificate("web", "site", "tls", ready="False", reason="Failed")],
                 certs_by_key={"c1": _cert(60)})
    assert rows[0]["status"] == k8s.NOT_READY
    assert rows[0]["breach"] is True


def test_expiry_status_wins_over_not_ready():
    rows = _rows([_secret("web", "tls", "c1")],
                 [_certificate("web", "site", "tls", ready="False")],
                 certs_by_key={"c1": _cert(-2)})
    assert rows[0]["status"] == "expired"


def test_certificate_without_secret_gets_own_row():
    rows = _rows([], [_certificate("web", "site", "missing", ready="False",
                                   reason="Issuing", not_after=None)])
    assert len(rows) == 1
    assert rows[0]["kind"] == "Certificate"
    assert rows[0]["status"] == k8s.NOT_READY
    assert rows[0]["days_until_expiry"] is None
    assert "missing" in rows[0]["error"]


def test_orphan_certificates_skipped_when_secrets_filtered():
    rows = _rows([], [_certificate("web", "site", "missing")], include_orphans=False)
    assert rows == []


def test_unparseable_secret_is_an_error_row_listed_first():
    rows = _rows([_secret("a", "ok", "c1"), _secret("b", "broken", "garbage")],
                 certs_by_key={"c1": _cert(100)})
    assert rows[0]["target"] == "b/broken"
    assert rows[0]["status"] == "error"
    assert rows[0]["breach"] is True


def test_excludes_by_namespace_and_issuer_glob():
    rows = _rows(
        [_secret("istio-system", "mesh", "c1"), _secret("app", "internal", "c2"),
         _secret("app", "managed", "c3"), _secret("app", "public", "c4")],
        [_certificate("app", "managed-cert", "managed", issuer="selfsigned-ca")],
        certs_by_key={"c1": _cert(1), "c2": _cert(2, issuer_cn="Internal Root CA"),
                      "c3": _cert(3, issuer_cn="selfsigned"), "c4": _cert(4)},
        exclude_namespaces=["istio-*"],
        exclude_issuers=["Internal *", "selfsigned-*"],
    )
    assert [r["target"] for r in rows] == ["app/public"]


def test_decode_tls_crt_reads_leaf_from_bundle(tmp_path, openssl_required):
    leaf = open(write_self_signed(tmp_path, cn="leaf.test")).read()
    other_dir = tmp_path / "other"
    other_dir.mkdir()
    other = open(write_self_signed(other_dir, cn="ca.test")).read()
    value = base64.b64encode((leaf + other).encode()).decode()
    assert k8s.decode_tls_crt(value)["subject"] == ((("commonName", "leaf.test"),),)


@pytest.mark.parametrize("value", ["not base64!", base64.b64encode(b"no pem").decode(), ""])
def test_decode_tls_crt_rejects_bad_values(value):
    with pytest.raises(CertCheckError):
        k8s.decode_tls_crt(value)


class FakeKubectl:
    def __init__(self, secrets, certificates=None, cert_manager=True):
        self.calls = []
        self.secrets = secrets
        self.certificates = certificates or []
        self.cert_manager = cert_manager

    def __call__(self, args):
        self.calls.append(args)
        if args[0] == "api-resources":
            names = ["certificates.cert-manager.io", "issuers.cert-manager.io"]
            return "\n".join(names) + "\n" if self.cert_manager else ""
        if args[:2] == ["get", "secrets"]:
            return json.dumps({"kind": "List", "items": self.secrets})
        if args[:2] == ["get", k8s.CERT_MANAGER_RESOURCE]:
            return json.dumps({"kind": "List", "items": self.certificates})
        raise AssertionError("unexpected kubectl call %r" % args)


def test_fetch_objects_scopes_and_selector():
    fake = FakeKubectl([_secret("a", "s", "x")], [_certificate("a", "c", "s")])
    objects = k8s.fetch_objects(fake, namespace=None, all_namespaces=True, selector="app=web")
    assert len(objects["secrets"]) == 1 and len(objects["certificates"]) == 1
    secrets_call = fake.calls[0]
    assert "--field-selector" in secrets_call
    assert "type=kubernetes.io/tls" in secrets_call
    assert "--all-namespaces" in secrets_call
    assert secrets_call[-2:] == ["--selector", "app=web"]
    certs_call = fake.calls[2]
    assert "--all-namespaces" in certs_call
    assert "--selector" not in certs_call


def test_fetch_objects_without_cert_manager():
    fake = FakeKubectl([], cert_manager=False)
    objects = k8s.fetch_objects(fake, namespace="web", all_namespaces=False, selector=None)
    assert objects["certificates"] == []
    assert objects["cert_manager"] is False
    assert fake.calls[0][-2:] == ["--namespace", "web"]
    assert len(fake.calls) == 2


def _pem_value(tmp_path, cn):
    d = tmp_path / cn
    d.mkdir()
    return base64.b64encode(open(write_self_signed(d, cn=cn)).read().encode()).decode()


def test_k8s_command_json(tmp_path, openssl_required, monkeypatch, capsys):
    fake = FakeKubectl([_secret("web", "tls", _pem_value(tmp_path, "web.test"))],
                       [_certificate("web", "site", "tls")])
    seen = {}

    def runner(kubectl, timeout, global_args):
        seen.update(kubectl=kubectl, timeout=timeout, global_args=global_args)
        return fake

    monkeypatch.setattr(k8s, "kubectl_runner", runner)
    rc = main(["k8s", "-A", "--json", "--context", "prod", "--kubeconfig", "/kc"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == EXIT_OK
    assert payload[0]["target"] == "web/tls"
    assert payload[0]["common_name"] == "web.test"
    assert payload[0]["certificate"]["name"] == "site"
    assert seen["global_args"] == ["--kubeconfig", "/kc", "--context", "prod"]


def test_k8s_command_breach_and_table(tmp_path, openssl_required, monkeypatch, capsys):
    fake = FakeKubectl([_secret("web", "tls", _pem_value(tmp_path, "web.test"))])
    monkeypatch.setattr(k8s, "kubectl_runner", lambda *a: fake)
    rc = main(["k8s", "--warn-days", "1000"])
    out = capsys.readouterr().out
    assert rc == EXIT_BREACH
    header, row = out.splitlines()
    assert header.split()[:4] == ["DAYS", "STATUS", "KIND", "NAMESPACE/NAME"]
    assert "expiring" in row and "web/tls" in row and "web.test" in row


def test_k8s_command_kubectl_failure(monkeypatch, capsys):
    def failing(args):
        raise CertCheckError("kubectl get secrets failed: forbidden")

    monkeypatch.setattr(k8s, "kubectl_runner", lambda *a: failing)
    rc = main(["k8s", "--json"])
    assert rc == EXIT_ERROR
    assert "forbidden" in json.loads(capsys.readouterr().err)["error"]


def test_k8s_namespace_flags_are_exclusive(capsys):
    assert main(["k8s", "-n", "web", "-A"]) == EXIT_ERROR
    assert "mutually exclusive" in capsys.readouterr().err


def _fake_binary(tmp_path, body):
    path = tmp_path / "kubectl"
    path.write_text("#!%s\nimport sys\n%s\n" % (sys.executable, body))
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return str(path)


def test_kubectl_runner_passes_arguments(tmp_path):
    binary = _fake_binary(tmp_path, "print(' '.join(sys.argv[1:]))")
    run = k8s.kubectl_runner(binary, timeout=2.5, global_args=["--context", "dev"])
    assert run(["get", "secrets"]).strip() == "--context dev --request-timeout=2.5s get secrets"


def test_kubectl_runner_reports_stderr(tmp_path):
    binary = _fake_binary(tmp_path, "sys.stderr.write('Forbidden\\n'); sys.exit(1)")
    with pytest.raises(CertCheckError, match="Forbidden"):
        k8s.kubectl_runner(binary)(["get", "secrets"])


def test_kubectl_runner_missing_binary(tmp_path):
    with pytest.raises(CertCheckError, match="kubectl not found"):
        k8s.kubectl_runner(os.path.join(str(tmp_path), "nope"))(["version"])
