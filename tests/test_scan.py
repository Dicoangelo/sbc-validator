"""Public scan endpoint: SSRF guard + grading, fully offline (DNS monkeypatched)."""
import socket
from datetime import date, timedelta
from pathlib import Path

from sbc_validator.models import Certificate, EKU
from sbc_validator.probe import HandshakeResult
from sbc_validator.rules.client import RuleClient
from sbc_validator.scan_server import scan

REPO = Path(__file__).resolve().parent.parent


def _bundle():
    return RuleClient().fetch("ms_direct_routing",
                              local_path=str(REPO / "rulesets" / "ms_direct_routing_2026-06.json"))


def _leaf(cn="sbc.contoso.com"):
    return Certificate(subject_cn=cn, sans=[cn], ekus=[EKU.SERVER_AUTH],
                       not_after=(date.today() + timedelta(days=200)).isoformat(),
                       issuer_cn="DigiCert")


def _addrinfo(ip):
    return lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 5061))]


def _ok_connector(host, **k):
    return HandshakeResult(reachable=True, tls_version="1.2",
                           cipher="ECDHE-RSA-AES256-GCM-SHA384", leaf=_leaf(host))


def test_scan_rejects_malformed_fqdn():
    assert "error" in scan("not a hostname", _bundle())
    assert "error" in scan("localhost", _bundle())          # no dot -> not a public FQDN


def test_scan_ssrf_blocks_private(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _addrinfo("10.0.0.5"))
    out = scan("sbc.internal.corp", _bundle(), connector=_ok_connector)
    assert "error" in out and "non-public" in out["error"]


def test_scan_ssrf_blocks_loopback(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _addrinfo("127.0.0.1"))
    assert "error" in scan("evil.example.com", _bundle(), connector=_ok_connector)


def test_scan_ssrf_blocks_link_local(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _addrinfo("169.254.169.254"))  # cloud metadata
    assert "error" in scan("metadata.example.com", _bundle(), connector=_ok_connector)


def test_scan_grades_public_target(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _addrinfo("8.8.8.8"))
    out = scan("sbc.contoso.com", _bundle(), connector=_ok_connector)
    assert out["grade"] == "A", out
    assert out["fqdn"] == "sbc.contoso.com"


def test_stats_aggregates_anonymized_log(tmp_path):
    """The /stats aggregator summarizes grades + check-IDs only; no FQDN ever in the log."""
    from sbc_validator.scan_server import stats
    p = tmp_path / "scans.jsonl"
    p.write_text("\n".join([
        '{"grade":"A","reachable":true,"checks":[]}',
        '{"grade":"C","reachable":true,"checks":["C.TLS.WEAK_VERSION"]}',
        '{"grade":"FAIL","reachable":true,"checks":["C.CERT.EXPIRY","C.TLS.WEAK_VERSION"]}',
    ]) + "\n")
    s = stats(str(p))
    assert s["total"] == 3 and s["reachable"] == 3
    assert s["grades"]["A"] == 1 and s["grades"]["FAIL"] == 1
    assert s["top_checks"][0]["check_id"] == "C.TLS.WEAK_VERSION"
    assert stats(None)["total"] == 0                       # no log -> empty, no crash
    assert stats(str(tmp_path / "nope.jsonl"))["total"] == 0
