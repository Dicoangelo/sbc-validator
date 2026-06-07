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


def test_unknown_config_raises():
    # All four vendors are implemented; unmatched text has no parser.
    with pytest.raises(ValueError):
        detect_and_parse("this is not any vendor's SBC config\n")


def test_oracle_parses_fourth_vendor():
    cfg = detect_and_parse((REPO / "samples" / "oracle_teams.acli").read_text())
    assert cfg.vendor == "oracle_acme"
    t = cfg.teams_interface()
    assert t is not None and t.transport == "tls"
    assert t.srtp_enabled is True          # realm media-sec-policy + sdes-profile
    assert t.options_keepalive is True     # session-agent ping-method OPTIONS
    assert "PCMU" in t.offered_codecs


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


# ---- call-flow simulation --------------------------------------------------

from sbc_validator.call_sim import simulate_call
from sbc_validator.validators.ca_compliance import CaComplianceValidator as _C
from sbc_validator.validators.interop import InteropValidator as _B
from sbc_validator.validators.nat_traversal import NatTraversalValidator as _D
from sbc_validator.validators.codec import CodecValidator as _E


def _all_findings(cfg, ruleset):
    fs = []
    for V in (SyntaxSemanticValidator, _B, _C, _D, _E):
        fs.extend(V(ruleset).validate(cfg).findings)
    return fs


def test_sim_clean_call_is_stable(ruleset):
    cfg = detect_and_parse((REPO / "samples" / "clean_pass.ini").read_text())
    sim = simulate_call(cfg, ruleset, _all_findings(cfg, ruleset))
    assert sim.outcome == "STABLE"
    assert sim.dies_at is None
    assert sim.negotiated_codec in ("PCMU", "G722")
    assert any("RTP" in line for line in sim.ladder)


def test_sim_missing_root_dies_at_tls(ruleset):
    cfg = detect_and_parse((REPO / "samples" / "audiocodes_min.ini").read_text())
    sim = simulate_call(cfg, ruleset, _all_findings(cfg, ruleset))
    assert sim.outcome == "NO_CONNECT"
    assert sim.dies_at == "TLS handshake"
    # ladder truncates at the handshake; it never reaches INVITE
    assert not any("INVITE" in line for line in sim.ladder)


def test_sim_one_way_audio_from_private_media(ruleset):
    # TLS/SIP/SDP all clean, but media advertises a private IP -> one-way audio
    cfg = NormalizedConfig(
        vendor="x", sbc_fqdn="sbc.example.com",
        sip_interfaces=[SipInterface(
            name="T", role="teams", fqdn="sbc.example.com", transport="tls",
            options_keepalive=True, offered_codecs=["PCMU", "G722"], dtmf_method="rfc2833",
            srtp_enabled=True,
            tls_context=TlsContext(
                name="T", mtls_enabled=True,
                trusted_root_ids=[r["name"] for r in ruleset["C"]["required_root_ca_ids"]],
                presented_cert=Certificate(
                    subject_cn="sbc.example.com", sans=["sbc.example.com"],
                    ekus=[EKU.SERVER_AUTH], not_after="2030-01-01", chain_complete=True)))],
        media_realms=[MediaRealm(name="m", advertised_public_ip="10.20.30.40", symmetric_rtp=True)])
    sim = simulate_call(cfg, ruleset, _all_findings(cfg, ruleset))
    assert sim.outcome == "ONE_WAY_AUDIO"
    assert sim.dies_at == "Media path"


def test_sim_488_when_no_teams_codec_overlap(ruleset):
    cfg = NormalizedConfig(
        vendor="x", sbc_fqdn="sbc.example.com",
        sip_interfaces=[SipInterface(
            name="T", role="teams", fqdn="sbc.example.com", transport="tls",
            options_keepalive=True, offered_codecs=["G723"],  # not Teams-supported
            tls_context=TlsContext(
                name="T", mtls_enabled=True,
                trusted_root_ids=[r["name"] for r in ruleset["C"]["required_root_ca_ids"]],
                presented_cert=Certificate(
                    subject_cn="sbc.example.com", sans=["sbc.example.com"],
                    ekus=[EKU.SERVER_AUTH], not_after="2030-01-01", chain_complete=True)))],
        media_realms=[MediaRealm(name="m", advertised_public_ip="80.0.0.5", symmetric_rtp=True)])
    sim = simulate_call(cfg, ruleset, _all_findings(cfg, ruleset))
    assert sim.outcome == "REJECTED"
    assert sim.dies_at == "SDP negotiation"
    assert any("488" in line for line in sim.ladder)


# ---- PCAP explainer (post-mortem) ------------------------------------------

from sbc_validator.pcap import read_packets
from sbc_validator.sip_trace import analyze

PCAP_CLEAN = REPO / "samples" / "clean_call.pcap"
PCAP_488 = REPO / "samples" / "reject_488.pcap"
PCAP_ONEWAY = REPO / "samples" / "one_way_audio.pcap"


def test_pcap_reader_parses_udp_sip():
    pkts = read_packets(str(PCAP_488))
    assert len(pkts) == 4
    assert all(p.proto == "udp" for p in pkts)
    assert any(b"INVITE" in p.payload for p in pkts)


def test_explain_clean_call_connected():
    r = analyze(str(PCAP_CLEAN))
    assert r["sip_messages"] == 7
    assert len(r["rtp_flows"]) == 2            # both directions -> two-way audio
    call = r["calls"][0]
    assert call["outcome"] == "CONNECTED"
    assert any("INVITE" in l for l in call["ladder"])


def test_explain_488_maps_to_codec_domain():
    r = analyze(str(PCAP_488))
    call = r["calls"][0]
    assert call["outcome"] == "REJECTED_488"
    assert call["offered_codecs"] == ["G729"]
    assert any(d["domain"] == "E" for d in call["diagnoses"])


def test_explain_one_way_audio_maps_to_nat_domain():
    r = analyze(str(PCAP_ONEWAY))
    call = r["calls"][0]
    assert call["outcome"] == "ONE_WAY_AUDIO"
    assert any(d["domain"] == "D" for d in call["diagnoses"])
    assert any("10.1.1.5" in d["detail"] for d in call["diagnoses"])


PCAP_TOPO = REPO / "samples" / "topology_leak.pcap"


def test_explain_topology_leak_maps_to_domain_f():
    r = analyze(str(PCAP_TOPO))
    call = r["calls"][0]
    assert call["outcome"] == "CONNECTED"          # call works, but leaks topology
    leak = [d for d in call["diagnoses"] if d["domain"] == "F"]
    assert leak and "10.9.9.9" in leak[0]["detail"]


# ---- SRTP media-encryption check (domain C) --------------------------------

def test_c_flags_missing_srtp(ruleset):
    cfg = detect_and_parse((REPO / "samples" / "audiocodes_min.ini").read_text())
    res = CaComplianceValidator(ruleset).validate(cfg)
    assert "C.SRTP.DISABLED" in ids(res.findings)


def test_c_no_srtp_finding_when_enabled(ruleset):
    cfg = detect_and_parse((REPO / "samples" / "clean_pass.ini").read_text())
    res = CaComplianceValidator(ruleset).validate(cfg)
    assert "C.SRTP.DISABLED" not in ids(res.findings)


def test_cube_and_ribbon_parse_srtp():
    cube = detect_and_parse((REPO / "samples" / "cisco_cube_dr.txt").read_text())
    ribbon = detect_and_parse((REPO / "samples" / "ribbon_sbc.cli").read_text())
    assert cube.teams_interface().srtp_enabled is True
    assert ribbon.teams_interface().srtp_enabled is True


# ---- real AudioCodes parameter-table .ini ----------------------------------

REAL_AC = REPO / "samples" / "audiocodes_teams_real.ini"


def test_real_audiocodes_ini_parses_and_resolves_teams_leg():
    cfg = detect_and_parse(REAL_AC.read_text())
    assert cfg.vendor == "audiocodes"
    assert cfg.raw_meta.get("parser") == "audiocodes/table-ini"
    assert cfg.sbc_fqdn == "sbc01.contoso.com"
    teams = cfg.teams_interface()                 # resolved via ProxySet -> pstnhub
    assert teams is not None
    assert teams.transport == "tls"
    assert teams.srtp_enabled is True             # EnableMediaSecurity=1 + behaviour 1
    assert teams.options_keepalive is True
    # AudioCodersGroups_Teams from the config note: PCMU/PCMA/G729/SILK (AMR-WB ignored)
    assert {"PCMU", "SILK"} <= set(teams.offered_codecs)


def test_real_audiocodes_ini_no_false_critical(ruleset):
    """A real .ini has no trust store / cert in it; C must NOT scream CRITICAL."""
    cfg = detect_and_parse(REAL_AC.read_text())
    res = CaComplianceValidator(ruleset).validate(cfg)
    found = ids(res.findings)
    assert "C.CA.TRUST_STORE_UNAVAILABLE" in found     # honest "verify out-of-band"
    assert "C.CA.ROOT_MISSING" not in found            # no false "all roots missing"
    assert "C.CERT.MISSING" not in found               # cert supplied via annotated PEM


def test_real_ini_normalization_from_manipulation_set(ruleset):
    """A leg with a message-manipulation set has normalization -> no false flag."""
    cfg = detect_and_parse(REAL_AC.read_text())
    assert cfg.teams_interface().normalization_profile  # e.g. "MsgManip:1"
    res = InteropValidator(ruleset).validate(cfg)
    assert "B.SIP.NO_NORMALIZATION" not in ids(res.findings)


def test_real_ini_nat_public_media_ip(ruleset):
    """Public media address comes from NATTranslation, not a MediaRealm IP field."""
    cfg = detect_and_parse(REAL_AC.read_text())
    assert cfg.media_realms and cfg.media_realms[0].advertised_public_ip == "80.0.0.30"
    res = NatTraversalValidator(ruleset).validate(cfg)
    found = ids(res.findings)
    assert "D.NAT.PRIVATE_ADVERTISED" not in found and "D.NAT.NO_PUBLIC_IP" not in found


def test_real_ini_routing_and_classification_resolved(ruleset):
    from sbc_validator.validators.routing import RoutingValidator
    cfg = detect_and_parse(REAL_AC.read_text())
    assert cfg.teams_classified is True
    assert ("teams", "carrier") in cfg.routes and ("carrier", "teams") in cfg.routes
    res = RoutingValidator(ruleset).validate(cfg)
    assert res.findings == []                          # fully routable + classified


def test_routing_silent_without_routing_info(ruleset):
    """Simplified/other-vendor configs carry no routing info -> validator stays silent."""
    from sbc_validator.validators.routing import RoutingValidator
    cfg = detect_and_parse((REPO / "samples" / "clean_pass.ini").read_text())
    assert cfg.routes == [] and cfg.teams_classified is None
    assert RoutingValidator(ruleset).validate(cfg).findings == []


def test_routing_flags_missing_route_and_unclassified(ruleset):
    from sbc_validator.validators.routing import RoutingValidator
    cfg = detect_and_parse(REAL_AC.read_text())
    cfg.routes = [("teams", "carrier")]                # drop inbound route
    cfg.teams_classified = False
    found = {f.check_id for f in RoutingValidator(ruleset).validate(cfg).findings}
    assert "G.ROUTE.NO_TO_TEAMS" in found
    assert "G.CLASS.UNCLASSIFIED" in found


def test_table_ini_reader_parses_format_and_data():
    from sbc_validator.parsers.audiocodes_ini import parse_table_ini
    g, tables = parse_table_ini(REAL_AC.read_text())
    assert g["EnableMediaSecurity"] == "1"
    assert len(tables["ProxyIP"]) == 3
    assert tables["IPGroup"][0]["Name"] == "Teams"
    # naming-tolerant: pstnhub FQDN captured verbatim
    assert any("pstnhub.microsoft.com" in r["IPAddress"] for r in tables["ProxyIP"])


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

# ---- trust-anchor chain validation -----------------------------------------

CHAIN = REPO / "samples" / "chain_fullchain.pem"
ROOT = REPO / "samples" / "chain_root.pem"


def _root_sha1():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    root = x509.load_pem_x509_certificate(ROOT.read_bytes())
    return root.fingerprint(hashes.SHA1()).hex().upper()


def test_verify_chain_real_signed_chain():
    if not cert_inspect.available():
        pytest.skip("cryptography not installed")
    r = cert_inspect.verify_chain(str(CHAIN))
    assert r["signatures_valid"] and r["reached_root"]
    assert r["leaf_self_signed"] is False
    assert r["terminal_sha1"] == _root_sha1()


def test_verify_chain_self_signed_leaf():
    if not cert_inspect.available():
        pytest.skip("cryptography not installed")
    r = cert_inspect.verify_chain(str(PEM))      # sbc01_leaf.pem (self-signed)
    assert r["leaf_self_signed"] is True and r["length"] == 1


def _ctx_with_cert(ruleset, pem_path):
    return NormalizedConfig(
        vendor="x", sbc_fqdn="sbc01.contoso.com",
        sip_interfaces=[SipInterface(
            name="T", role="teams", fqdn="sbc01.contoso.com", transport="tls",
            srtp_enabled=True, options_keepalive=True, offered_codecs=["PCMU"],
            tls_context=TlsContext(
                name="T", mtls_enabled=True,
                trusted_root_ids=[r["name"] for r in ruleset["C"]["required_root_ca_ids"]],
                presented_cert=Certificate(source_file=str(pem_path))))])


def test_c_flags_untrusted_anchor(ruleset):
    """Real chain to a non-Microsoft root -> UNTRUSTED_ANCHOR (production ruleset)."""
    if not cert_inspect.available():
        pytest.skip("cryptography not installed")
    cfg = _ctx_with_cert(ruleset, CHAIN)
    found = ids(CaComplianceValidator(ruleset).validate(cfg).findings)
    assert "C.CERT.UNTRUSTED_ANCHOR" in found
    assert "C.CERT.SELF_SIGNED" not in found


def test_c_anchored_when_root_is_trusted(ruleset):
    """Same chain, but with the test root's SHA-1 in the trusted set -> ANCHORED."""
    if not cert_inspect.available():
        pytest.skip("cryptography not installed")
    import copy
    rs = copy.deepcopy(ruleset)
    rs["C"]["required_root_ca_ids"] = [{"name": "SBC Test Root CA", "sha1": _root_sha1()}]
    cfg = _ctx_with_cert(rs, CHAIN)
    found = ids(CaComplianceValidator(rs).validate(cfg).findings)
    assert "C.CERT.CHAIN_ANCHORED" in found
    assert "C.CERT.UNTRUSTED_ANCHOR" not in found


def test_c_flags_self_signed_leaf(ruleset):
    if not cert_inspect.available():
        pytest.skip("cryptography not installed")
    cfg = _ctx_with_cert(ruleset, PEM)
    found = ids(CaComplianceValidator(ruleset).validate(cfg).findings)
    assert "C.CERT.SELF_SIGNED" in found


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


# ---- CI gate (--fail-on threshold) -----------------------------------------

from sbc_validator.cli import main as _cli_main

_R = str(REPO / "rulesets" / "ms_direct_routing_2026-06.json")


def _validate_rc(sample, *extra):
    return _cli_main(["validate", str(REPO / "samples" / sample), "--ruleset", _R, *extra])


def test_gate_default_blocks_only_on_block():
    assert _validate_rc("review_high.ini") == 0          # REVIEW passes default gate
    assert _validate_rc("audiocodes_min.ini") == 1       # BLOCK fails


def test_gate_fail_on_review():
    assert _validate_rc("review_high.ini", "--fail-on", "review") == 1
    assert _validate_rc("clean_pass.ini", "--fail-on", "review") == 0


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
