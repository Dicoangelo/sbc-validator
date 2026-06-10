"""Outside-in `probe` grading — fully offline via an injected connector."""
from datetime import date, timedelta
from pathlib import Path

from sbc_validator.models import Certificate, EKU
from sbc_validator.probe import HandshakeResult, grade_endpoint, probe
from sbc_validator.rules.client import RuleClient

REPO = Path(__file__).resolve().parent.parent
RULESET = REPO / "rulesets" / "ms_direct_routing_2026-06.json"


def _bundle():
    return RuleClient().fetch("ms_direct_routing", local_path=str(RULESET))


def _leaf(cn="sbc.contoso.com", days=365, eku=(EKU.SERVER_AUTH,)):
    return Certificate(subject_cn=cn, sans=[cn], ekus=list(eku),
                       not_after=(date.today() + timedelta(days=days)).isoformat(),
                       issuer_cn="DigiCert")


def test_probe_clean_edge_grades_A():
    hs = HandshakeResult(reachable=True, tls_version="1.2",
                         cipher="ECDHE-RSA-AES256-GCM-SHA384", leaf=_leaf())
    g = grade_endpoint(hs, "sbc.contoso.com", _bundle())
    assert g["grade"] == "A", g
    assert g["issues"] == []


def test_probe_weak_tls_flagged():
    hs = HandshakeResult(reachable=True, tls_version="1.0",
                         cipher="ECDHE-RSA-AES256-GCM-SHA384", leaf=_leaf())
    g = grade_endpoint(hs, "sbc.contoso.com", _bundle())
    assert "C.TLS.WEAK_VERSION" in {i["check_id"] for i in g["issues"]}
    assert g["grade"] == "C"


def test_probe_expired_leaf_fails():
    hs = HandshakeResult(reachable=True, tls_version="1.2",
                         cipher="ECDHE-RSA-AES256-GCM-SHA384", leaf=_leaf(days=-1))
    g = grade_endpoint(hs, "sbc.contoso.com", _bundle())
    assert "C.CERT.EXPIRY" in {i["check_id"] for i in g["issues"]}
    assert g["grade"] == "FAIL"


def test_probe_unreachable_is_inconclusive_not_fail():
    """An SBC that firewalls us out must NOT be graded a failure."""
    hs = HandshakeResult(reachable=False, error="TimeoutError: timed out")
    g = grade_endpoint(hs, "sbc.contoso.com", _bundle())
    assert g["grade"] == "INCONCLUSIVE"
    assert g["reachable"] is False


def test_probe_injected_connector_touches_no_network():
    """probe() does all I/O through the injected connector; the MS-edge reference
    is reached the same way. Proves no real socket is opened in tests."""
    calls = []

    def fake(host, *a, **k):
        calls.append(host)
        return HandshakeResult(reachable=True, tls_version="1.2",
                               cipher="ECDHE-RSA-AES256-GCM-SHA384", leaf=_leaf(cn=host))

    rep = probe("sbc.contoso.com", _bundle(), connector=fake, check_ms_edge=True)
    assert rep["customer"]["grade"] == "A"
    assert "sip.g1.pstnhub.microsoft.com" in calls
    assert rep["microsoft_edge"]["reachable"] is True
