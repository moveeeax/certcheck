from datetime import datetime, timedelta, timezone

from certcheck.core import (
    EXPIRED,
    EXPIRING,
    HOSTNAME_MISMATCH,
    NOT_YET_VALID,
    UNTRUSTED,
    X509_V_ERR_CERT_HAS_EXPIRED,
    X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT,
    X509_V_ERR_HOSTNAME_MISMATCH,
    X509_V_ERR_IP_ADDRESS_MISMATCH,
    X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN,
    X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY,
    apply_verify_failure,
    chain_findings,
    evaluate,
    forward_secret,
    parse_cert,
    protocol_findings,
)
from tests.conftest import make_cert_dict

NOW = datetime(2021, 6, 1, 12, 0, 0, tzinfo=timezone.utc)


def _pair(days_from_now, cn="leaf.test", issuer_cn="Test CA", lifetime_days=3650):
    not_after = NOW + timedelta(days=days_from_now)
    info = parse_cert(make_cert_dict(not_after - timedelta(days=lifetime_days), not_after,
                                     cn=cn, issuer_cn=issuer_cn))
    return info, evaluate(info, warn_days=30, now=NOW)


def _checks(findings):
    return [f["check"] for f in findings]


def test_verify_failure_on_valid_dates_is_untrusted():
    _, status = _pair(200)
    folded = apply_verify_failure(status, X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY)
    assert folded.status == UNTRUSTED
    assert folded.breach is True
    assert folded.days_until_expiry == 200


def test_verify_failure_keeps_expired_status():
    _, status = _pair(-3)
    folded = apply_verify_failure(status, X509_V_ERR_CERT_HAS_EXPIRED)
    assert folded.status == EXPIRED
    assert folded.days_until_expiry < 0


def test_verify_failure_keeps_not_yet_valid_status():
    info = parse_cert(make_cert_dict(NOW + timedelta(days=1), NOW + timedelta(days=90)))
    status = evaluate(info, now=NOW)
    assert apply_verify_failure(status, 9).status == NOT_YET_VALID


def test_verify_failure_name_mismatch_codes():
    _, status = _pair(5)  # expiring, but the mismatch is the headline
    assert apply_verify_failure(status, X509_V_ERR_HOSTNAME_MISMATCH).status == HOSTNAME_MISMATCH
    assert apply_verify_failure(status, X509_V_ERR_IP_ADDRESS_MISMATCH).status == HOSTNAME_MISMATCH


def test_self_signed_property():
    assert _pair(10, cn="x", issuer_cn="x")[0].self_signed is True
    assert _pair(10, cn="x", issuer_cn="CA")[0].self_signed is False


def test_chain_findings_clean_chain():
    assert chain_findings([_pair(200), _pair(900, cn="Test CA", issuer_cn="Root")]) == []


def test_chain_findings_expired_and_expiring_intermediates():
    chain = [_pair(200), _pair(-1, cn="Old CA"), _pair(10, cn="Root", issuer_cn="Root")]
    findings = chain_findings(chain)
    assert _checks(findings) == ["chain_" + EXPIRED, "chain_" + EXPIRING]
    assert "Old CA" in findings[0]["detail"]


def test_chain_findings_leaf_expiry_is_not_repeated():
    assert chain_findings([_pair(-5)]) == []


def test_chain_findings_self_signed_leaf():
    chain = [_pair(200, cn="x", issuer_cn="x")]
    assert _checks(chain_findings(chain, X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT, "self-signed")) \
        == ["self_signed"]


def test_chain_findings_trusted_self_signed_is_fine():
    # Verified (e.g. via --ca-file): no verify_code, so nothing to report.
    assert chain_findings([_pair(200, cn="x", issuer_cn="x")]) == []


def test_chain_findings_hostname_mismatch():
    assert _checks(chain_findings([_pair(200)], X509_V_ERR_HOSTNAME_MISMATCH)) \
        == ["hostname_mismatch"]


def test_chain_findings_incomplete_chain():
    findings = chain_findings([_pair(200)], X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY)
    assert _checks(findings) == ["incomplete_chain"]
    assert "leaf.test" in findings[0]["detail"]


def test_chain_findings_untrusted_root_uses_verify_message():
    chain = [_pair(200), _pair(900, cn="Private Root", issuer_cn="Private Root")]
    findings = chain_findings(chain, X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN,
                              "self-signed certificate in certificate chain")
    assert _checks(findings) == ["untrusted"]
    assert findings[0]["detail"] == "self-signed certificate in certificate chain"


def test_chain_findings_expiry_code_not_duplicated():
    chain = [_pair(200), _pair(-1, cn="Old CA")]
    assert _checks(chain_findings(chain, X509_V_ERR_CERT_HAS_EXPIRED, "certificate has expired")) \
        == ["chain_expired"]


def test_chain_findings_without_trust_checks():
    chain = [_pair(200, cn="x", issuer_cn="x"), _pair(-1, cn="Old CA")]
    findings = chain_findings(chain, X509_V_ERR_HOSTNAME_MISMATCH, check_trust=False)
    assert _checks(findings) == ["chain_expired"]


def test_protocol_findings():
    accepted = {"TLSv1.0": True, "TLSv1.1": None, "TLSv1.2": True, "TLSv1.3": True}
    findings = protocol_findings(accepted, "TLSv1.2")
    assert [f["detail"].split()[0] for f in findings] == ["TLSv1.0"]
    assert protocol_findings(accepted, "TLSv1.0") == []
    assert len(protocol_findings(accepted, "TLSv1.3")) == 2


def test_forward_secret():
    assert forward_secret("kx-ecdhe")
    assert forward_secret("kx-dhe")
    assert forward_secret("kx-any")  # TLS 1.3
    assert not forward_secret("kx-rsa")
    assert not forward_secret(None)
