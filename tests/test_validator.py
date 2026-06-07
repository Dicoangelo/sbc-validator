"""Smoke + unit tests for the SBC validator skeleton."""
import json
from pathlib import Path

import pytest

from sbc_validator.parsers.audiocodes import (
    AudioCodesParser, detect_and_parse, CiscoCubeParser, RibbonParser,
)
from sbc_validator.parsers.audiocodes import OracleAcmeParser
from sbc_validator.report.html import render_html
from sbc_validator.validators.ha_drift import ha_diff
from sbc_validator.models import (
    EKU, Certificate, MediaRealm, NormalizedConfig, SipInterface, TlsContext,
)
from sbc_validator.validators.ca_compliance import CaComplianceValidator
from sbc_validator.validators.nat_traversal import NatTraversalValidator
from sbc_validator.validators.interop import InteropValidator
from sbc_validator.validators.codec import CodecValidator
from sbc_validator.validators.syntax_semantic import SyntaxSemanticValidator
from sbc_validator.rules.client import (
    RuleClient, RuleVerificationError, sign_bundle, load_private_key,
)
from sbc_validator import cert_inspect
from sbc_validator.report.risk import score
from sbc_validator.validators.base import Severity

REPO = Path(__file__).resolve().parent.parent
SAMPLE = REPO / "samples" / "audiocodes_min.ini"
RULESET = REPO / "rulesets" / "ms_direct_routing_2026-06.json"
PEM = REPO / "samples" / "sbc01_leaf.pem"


@pytest.fixture
def ruleset():
    return RuleClient().fetch("ms_direct_routing", local_path=str(RULESET))


def ids(findings):
    return {f.check_id for f in findings}


# ---- parser ----------------------------------------------------------------

def test_audiocodes_sniff_and_parse():
    text = SAMPLE.read_text()
    assert AudioCodesParser.sniff(text)
    cfg = detect_and_parse(text)
    assert cfg.vendor == "audiocodes"
    assert cfg.sbc_fqdn == "sbc01.contoso.com"
    assert cfg.teams_interface() is not None


def test_unimplemented_parser_raises():
    # AudioCodes, Cisco CUBE, and Ribbon are implemented; Oracle is still a stub.
    p = OracleAcmeParser()
    with pytest.raises(NotImplementedError):
        p.parse("sip-interface\nrealm-config")


# ---- Cisco CUBE parser (second vendor — vendor-agnostic proof) --------------

CUBE = REPO / "samples" / "cisco_cube_dr.txt"


def test_cube_sniff_and_parse():
    text = CUBE.read_text()
    assert CiscoCubeParser.sniff(text)
    cfg = detect_and_parse(text)
    assert cfg.vendor == "cisco_cube"
    assert cfg.sbc_fqdn == "cube-sbc-01.contoso.com"
    teams = cfg.teams_interface()
    assert teams is not None
    assert teams.transport == "tls"
    assert teams.options_keepalive is True
    # tenant 100 references codec class 1 -> G722/PCMU normalized
    assert "G722" in teams.offered_codecs


def test_cube_same_validators_flag_missing_root(ruleset):
    """The AudioCodes-shaped C validator runs unmodified on Cisco output."""
    cfg = detect_and_parse(CUBE.read_text())
    res = CaComplianceValidator(ruleset).validate(cfg)
    found = ids(res.findings)
    assert "C.CA.ROOT_MISSING" in found            # 6 of 7 roots -> the 2026 wedge
    assert "C.CERT.EKU_NO_SERVERAUTH" not in found  # real PEM has serverAuth -> no false positive


def test_cube_blocks_end_to_end(ruleset):
    from sbc_validator.validators.interop import InteropValidator as IV
    cfg = detect_and_parse(CUBE.read_text())
    findings = []
    for V in (SyntaxSemanticValidator, IV, CaComplianceValidator,
              NatTraversalValidator, CodecValidator):
        findings.extend(V(ruleset).validate(cfg).findings)
    assert score(findings)["verdict"] == "BLOCK"


# ---- Ribbon parser (third vendor) ------------------------------------------

RIBBON = REPO / "samples" / "ribbon_sbc.cli"


def test_ribbon_sniff_and_parse():
    text = RIBBON.read_text()
    assert RibbonParser.sniff(text)
    cfg = detect_and_parse(text)
    assert cfg.vendor == "ribbon"
    assert cfg.sbc_fqdn == "sbc-ribbon-01.contoso.com"
    teams = cfg.teams_interface()
    assert teams is not None and teams.transport == "tls"
    assert teams.options_keepalive is True
    assert teams.normalization_profile == "NORMALIZE_TEAMS"
    assert "G722" in teams.offered_codecs and "PCMU" in teams.offered_codecs


def test_ribbon_eku_review_not_block(ruleset):
    """Third vendor, same C validator: clientAuth-only leaf -> HIGH, roots all present."""
    cfg = detect_and_parse(RIBBON.read_text())
    res = CaComplianceValidator(ruleset).validate(cfg)
    found = ids(res.findings)
    assert "C.CERT.EKU_NO_SERVERAUTH" in found
    assert "C.CA.ROOT_MISSING" not in found     # all 7 roots present


# ---- HA drift detection ----------------------------------------------------

ACTIVE = REPO / "samples" / "clean_pass.ini"
STANDBY = REPO / "samples" / "audiocodes_standby.ini"


def test_ha_drift_flags_trust_store_and_keepalive():
    a = detect_and_parse(ACTIVE.read_text())
    s = detect_and_parse(STANDBY.read_text())
    findings = ha_diff(a, s)
    found = {f.check_id for f in findings}
    assert "HA.DRIFT.TRUST_STORE" in found       # CRITICAL: failover-during-CA-rotation risk
    assert "HA.DRIFT.KEEPALIVE" in found
    assert score(findings)["verdict"] == "BLOCK"


def test_ha_no_drift_when_identical():
    a = detect_and_parse(ACTIVE.read_text())
    assert ha_diff(a, a) == []


# ---- ruleset signing -------------------------------------------------------

def test_signed_ruleset_verifies(ruleset):
    assert ruleset["bundle_version"] == "2026-06-07"
    roots = ruleset["C"]["required_root_ca_ids"]
    assert len(roots) == 7
    names = {r["name"] for r in roots}
    # Authority guard: the new DigiCert G5 pair MUST be present and the retired
    # Baltimore root and the bogus 2018 placeholder MUST be absent. This catches a
    # wrong-but-still-7 list (the exact pre-2026-06-07 bug).
    assert "DigiCert TLS ECC P384 Root G5" in names
    assert "DigiCert TLS RSA 4096 Root G5" in names
    assert not any("Baltimore" in n for n in names)
    assert not any("2018" in n for n in names)
    # every required root carries a SHA-1 thumbprint
    assert all(r.get("sha1") for r in roots)


def test_tampered_ruleset_rejected(tmp_path):
    bundle = json.loads(RULESET.read_text())
    bundle["C"]["cert_expiry_warn_days"] = 9999  # tamper after signing
    p = tmp_path / "tampered.json"
    p.write_text(json.dumps(bundle))
    with pytest.raises(RuleVerificationError):
        RuleClient(cache_dir=tmp_path).fetch("x", local_path=str(p))


def test_resign_roundtrip(tmp_path):
    bundle = json.loads(RULESET.read_text())
    bundle.pop("signature")
    bundle["C"]["cert_expiry_warn_days"] = 45
    resigned = sign_bundle(bundle, load_private_key(str(REPO / "dev" / "dev_signing_key.pem")))
    p = tmp_path / "resigned.json"
    p.write_text(json.dumps(resigned))
    out = RuleClient(cache_dir=tmp_path).fetch("x", local_path=str(p))
    assert out["C"]["cert_expiry_warn_days"] == 45


# ---- C validator -----------------------------------------------------------

def test_c_flags_missing_roots(ruleset):
    cfg = detect_and_parse(SAMPLE.read_text())
    res = CaComplianceValidator(ruleset).validate(cfg)
    assert "C.CA.ROOT_MISSING" in ids(res.findings)


def test_c_all_roots_present_no_root_finding(ruleset):
    root_names = [r["name"] for r in ruleset["C"]["required_root_ca_ids"]]
    cfg = NormalizedConfig(
        vendor="x", sbc_fqdn="sbc.example.com",
        sip_interfaces=[SipInterface(
            name="T", role="teams", fqdn="sbc.example.com",
            tls_context=TlsContext(
                name="T", mtls_enabled=True, trusted_root_ids=list(root_names),
                presented_cert=Certificate(
                    subject_cn="sbc.example.com", sans=["sbc.example.com"],
                    ekus=[EKU.SERVER_AUTH], not_after="2030-01-01", chain_complete=True),
            ))])
    res = CaComplianceValidator(ruleset).validate(cfg)
    assert "C.CA.ROOT_MISSING" not in ids(res.findings)
    assert "C.CERT.FQDN_MISMATCH" not in ids(res.findings)


def test_c_root_matching_is_naming_tolerant(ruleset):
    """Abbreviated config tokens (CA) match authoritative names (Certificate
    Authority), and thumbprints match too."""
    cfg = NormalizedConfig(
        vendor="x", sbc_fqdn="sbc.example.com",
        sip_interfaces=[SipInterface(
            name="T", role="teams", fqdn="sbc.example.com",
            tls_context=TlsContext(
                name="T", mtls_enabled=True,
                trusted_root_ids=[
                    "DigiCertGlobalRootCA", "DigiCertGlobalRootG2", "DigiCertGlobalRootG3",
                    "DigiCertTLSECCP384RootG5", "DigiCertTLSRSA4096RootG5",
                    "MicrosoftECCRootCA2017",            # abbrev of '...Certificate Authority 2017'
                    "73A5E64A3BFF8316FF0EDCCC618A906E4EAE4D74",  # MS RSA root by SHA-1 thumbprint
                ],
                presented_cert=Certificate(
                    subject_cn="sbc.example.com", sans=["sbc.example.com"],
                    ekus=[EKU.SERVER_AUTH], not_after="2030-01-01", chain_complete=True),
            ))])
    res = CaComplianceValidator(ruleset).validate(cfg)
    assert "C.CA.ROOT_MISSING" not in ids(res.findings)


# ---- D validator -----------------------------------------------------------

def test_d_flags_private_advertised(ruleset):
    cfg = NormalizedConfig(vendor="x", media_realms=[
        MediaRealm(name="m", advertised_public_ip="10.0.0.5", symmetric_rtp=False)])
    res = NatTraversalValidator(ruleset).validate(cfg)
    assert "D.NAT.PRIVATE_ADVERTISED" in ids(res.findings)


def test_d_public_ip_ok(ruleset):
    cfg = NormalizedConfig(vendor="x", media_realms=[
        MediaRealm(name="m", advertised_public_ip="8.8.8.8", symmetric_rtp=True)])
    res = NatTraversalValidator(ruleset).validate(cfg)
    assert "D.NAT.PRIVATE_ADVERTISED" not in ids(res.findings)
    assert "D.NAT.NO_SYMMETRIC_RTP" not in ids(res.findings)


# ---- B validator -----------------------------------------------------------

def test_b_flags_non_tls_transport(ruleset):
    cfg = detect_and_parse(SAMPLE.read_text())
    res = InteropValidator(ruleset).validate(cfg)
    assert "B.SIP.TRANSPORT" in ids(res.findings)


# ---- E validator -----------------------------------------------------------

def test_e_flags_no_cross_overlap(ruleset):
    cfg = detect_and_parse(SAMPLE.read_text())
    res = CodecValidator(ruleset).validate(cfg)
    assert "E.CODEC.NO_CROSS_OVERLAP" in ids(res.findings)


# ---- cert inspection -------------------------------------------------------

def test_cert_inspect_reads_real_pem():
    if not cert_inspect.available():
        pytest.skip("cryptography not installed")
    cert = cert_inspect.inspect_file(str(PEM))
    assert cert is not None
    assert cert.subject_cn == "sbc01.contoso.com"
    assert "sbc01.contoso.com" in cert.sans
    assert EKU.SERVER_AUTH in cert.ekus


# ---- A validator -----------------------------------------------------------

def test_a_flags_missing_fqdn_and_no_interfaces():
    cfg = NormalizedConfig(vendor="x")  # nothing in it
    res = SyntaxSemanticValidator({}).validate(cfg)
    found = ids(res.findings)
    assert "A.STRUCT.NO_SIP_INTERFACES" in found
    assert "A.SEM.MISSING_FQDN" in found


def test_a_flags_malformed_fqdn():
    cfg = NormalizedConfig(vendor="x", sbc_fqdn="not a hostname",
                           sip_interfaces=[SipInterface(name="i")])
    res = SyntaxSemanticValidator({}).validate(cfg)
    assert "A.SYN.FQDN_FORMAT" in ids(res.findings)


def test_a_dangling_tls_reference():
    cfg = NormalizedConfig(vendor="x", sbc_fqdn="sbc.example.com",
        sip_interfaces=[SipInterface(name="T", transport="tls", tls_context=None)])
    res = SyntaxSemanticValidator({}).validate(cfg)
    assert "A.SEM.DANGLING_TLS" in ids(res.findings)


def test_a_clean_config_no_findings():
    cfg = NormalizedConfig(vendor="x", sbc_fqdn="sbc.example.com",
        sip_interfaces=[SipInterface(name="T", transport="tls",
            tls_context=TlsContext(name="T"))])
    res = SyntaxSemanticValidator({}).validate(cfg)
    assert not res.findings


# ---- risk scoring ----------------------------------------------------------

def test_critical_forces_block():
    from sbc_validator.validators.base import Finding
    f = Finding("X", "t", Severity.CRITICAL, "d", "r")
    assert score([f])["verdict"] == "BLOCK"


def test_clean_passes():
    assert score([])["verdict"] == "PASS"


# ---- HTML report -----------------------------------------------------------

def test_html_report_renders_and_escapes():
    report = {
        "sbc": "sbc01.contoso.com", "vendor": "audiocodes", "site": "EU-West",
        "ruleset_version": "2026-06-02", "validated_at": "2026-06-06T00:00:00+00:00",
        "summary": {"risk_score": 100, "verdict": "BLOCK",
                    "counts": {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}},
        "findings": [{"check_id": "C.CA.ROOT_MISSING", "title": "roots <missing>",
                      "severity": "CRITICAL", "detail": "d", "remediation": "r",
                      "locator": "ctx", "domain": "C"}],
    }
    out = render_html(report)
    assert "<!doctype html>" in out.lower()
    assert "BLOCK" in out and "sbc01.contoso.com" in out
    assert "C.CA.ROOT_MISSING" in out
    assert "<missing>" not in out and "&lt;missing&gt;" in out  # escaped, no injection
