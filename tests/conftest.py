import shutil
import subprocess

from datetime import datetime, timezone

import pytest


def asn1_time(dt: datetime) -> str:
    """Render a datetime as an OpenSSL-style ASN.1 GMT time string."""
    return dt.strftime("%b %e %H:%M:%S %Y GMT").replace("  ", " ")


def make_cert_dict(not_before: datetime, not_after: datetime, cn="example.test",
                   issuer_cn="Test CA", san=("example.test", "www.example.test")):
    """Build a getpeercert-style dict for use in unit tests."""
    return {
        "subject": ((("commonName", cn),),),
        "issuer": ((("commonName", issuer_cn),),),
        "subjectAltName": tuple(("DNS", name) for name in san),
        "notBefore": asn1_time(not_before),
        "notAfter": asn1_time(not_after),
        "serialNumber": "01AB",
        "version": 3,
    }


def _openssl_available() -> bool:
    return shutil.which("openssl") is not None


def write_self_signed(path_dir, days_valid=365, cn="example.test"):
    """Create a self-signed PEM cert on disk and return its path.

    Classification (valid / expiring / expired) is driven in tests by
    evaluating against a chosen ``now`` rather than by backdating the
    certificate, which keeps generation portable across openssl builds.
    """
    key_path = str(path_dir / "key.pem")
    cert_path = str(path_dir / (cn + ".pem"))
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", key_path, "-out", cert_path,
            "-days", str(days_valid),
            "-subj", "/CN=%s" % cn,
            "-addext", "subjectAltName=DNS:%s,DNS:www.%s" % (cn, cn),
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return cert_path


@pytest.fixture
def now_utc():
    return datetime(2021, 6, 1, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def openssl_required():
    if not _openssl_available():
        pytest.skip("openssl binary not available")
