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
from sbc_validator.rules import client as rules_client
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


@pytest.fixture
def signing_key(monkeypatch):
    """Ephemeral publisher key for tests that must re-sign a bundle.

    Pins the verifier to this key's public half in-process, so the real
    production private key never has to live in the repo. Opt-in per test;
    tests that verify the real shipped ruleset do NOT use this fixture.
    """
    import base64
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    k = Ed25519PrivateKey.generate()
    pub = base64.b64encode(k.public_key().public_bytes_raw()).decode()
    monkeypatch.setattr(rules_client, "_PINNED_PUBLIC_KEY_B64", pub)
    return k


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


# ---- TLS version + cipher policy (ruleset-driven, previously unenforced) ----

def test_tls_weak_version_and_cipher_flagged(ruleset):
    """The ruleset declares tls_min_version + allowed_sip_cipher_suites; a config
    that pins TLS 1.0 and a non-accepted cipher set must now be caught (closes the
    rule-defined-but-unenforced gap)."""
    cfg = detect_and_parse((REPO / "samples" / "audiocodes_weak_tls.ini").read_text())
    found = ids(CaComplianceValidator(ruleset).validate(cfg).findings)
    assert "C.TLS.WEAK_VERSION" in found            # TLS 1.0 floor < required 1.2
    assert "C.TLS.CIPHER_NOT_ALLOWED" in found       # zero overlap with allowlist


def test_tls_policy_silent_when_not_carried(ruleset):
    """Tristate safety: a config that expresses no TLS floor or cipher list must
    produce neither finding (no false BLOCK on a clean config)."""
    cfg = detect_and_parse((REPO / "samples" / "clean_pass.ini").read_text())
    found = ids(CaComplianceValidator(ruleset).validate(cfg).findings)
    assert "C.TLS.WEAK_VERSION" not in found
    assert "C.TLS.CIPHER_NOT_ALLOWED" not in found


def test_cipher_name_normalization_iana_openssl():
    """IANA and OpenSSL spellings of the same suite must compare equal, so an
    OpenSSL-named config is judged against the IANA-named allowlist correctly."""
    from sbc_validator.validators.tls_policy import _canon_cipher
    assert _canon_cipher("ECDHE-RSA-AES256-GCM-SHA384") == \
           _canon_cipher("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")


def test_all_vendors_capture_tls_version_and_cipher(ruleset):
    """Every vendor parser captures the TLS floor + cipher into the model, in its
    native spelling, and that spelling canonicalizes to the ruleset's allowlist.
    Proves the cross-vendor wiring (Cisco lowercase-dashed, Ribbon IANA, Oracle/
    AudioCodes OpenSSL) feeds the same vendor-neutral domain-C check."""
    from sbc_validator.validators.tls_policy import _canon_cipher
    allow = {_canon_cipher(c) for c in ruleset["C"]["allowed_sip_cipher_suites"]}
    for fname in ("cisco_cube_dr.txt", "ribbon_sbc.cli",
                  "oracle_teams.acli", "audiocodes_teams_real.ini"):
        cfg = detect_and_parse((REPO / "samples" / fname).read_text())
        ctx = cfg.teams_interface().tls_context
        assert ctx.min_tls_version == "1.2", fname
        assert ctx.cipher_suites, fname
        assert any(_canon_cipher(c) in allow for c in ctx.cipher_suites), fname


# ---- Domain B: OPTIONS interval + carrier Contact FQDN + wildcard cert ------

def test_options_interval_out_of_range_flagged(ruleset):
    """MS requires OPTIONS pings every 60-180s; 300s must be flagged."""
    from sbc_validator.validators.interop import InteropValidator
    cfg = detect_and_parse((REPO / "samples" / "audiocodes_carrier.ini").read_text())
    assert "B.SIP.OPTIONS_INTERVAL" in ids(InteropValidator(ruleset).validate(cfg).findings)


def test_carrier_contact_fqdn_outside_domain_flagged(ruleset):
    """Direct Routing finds the tenant from the Contact FQDN; one outside the SBC's
    registered domain (contoso.com vs ...adatum.biz) must be flagged."""
    from sbc_validator.validators.interop import InteropValidator
    cfg = detect_and_parse((REPO / "samples" / "audiocodes_carrier.ini").read_text())
    assert "B.SIP.CONTACT_FQDN" in ids(InteropValidator(ruleset).validate(cfg).findings)


def test_wildcard_cert_not_flagged_for_carrier(ruleset):
    """A wildcard cert (*.sbc1.adatum.biz) is valid for multi-tenant hosting and
    must NOT trigger C.CERT.FQDN_MISMATCH for teams.sbc1.adatum.biz."""
    cfg = detect_and_parse((REPO / "samples" / "audiocodes_carrier.ini").read_text())
    assert "C.CERT.FQDN_MISMATCH" not in ids(CaComplianceValidator(ruleset).validate(cfg).findings)


def test_new_b_checks_silent_when_not_carried(ruleset):
    """Tristate: a config with no OPTIONS interval / Contact FQDN fires neither."""
    from sbc_validator.validators.interop import InteropValidator
    cfg = detect_and_parse((REPO / "samples" / "clean_pass.ini").read_text())
    found = ids(InteropValidator(ruleset).validate(cfg).findings)
    assert "B.SIP.OPTIONS_INTERVAL" not in found and "B.SIP.CONTACT_FQDN" not in found


def test_wildcard_and_registered_domain_helpers():
    from sbc_validator.validators.cert_checks import _name_covers
    from sbc_validator.validators.interop import _same_registered_domain
    assert _name_covers("*.sbc1.adatum.biz", "teams.sbc1.adatum.biz")
    assert not _name_covers("*.sbc1.adatum.biz", "sbc1.adatum.biz")        # apex not covered
    assert not _name_covers("*.sbc1.adatum.biz", "a.b.sbc1.adatum.biz")    # exactly one label
    assert _same_registered_domain("contoso.sbc1.adatum.biz", "sbc1.adatum.biz")
    assert not _same_registered_domain("contoso.com", "sbc1.adatum.biz")


def test_options_interval_captured_across_vendors():
    """Cisco (up-interval), Oracle (ping-interval), real-AudioCodes (ProxyKeepAliveTime)
    all feed the same vendor-neutral OPTIONS-interval field."""
    for fname in ("cisco_cube_dr.txt", "oracle_teams.acli", "audiocodes_teams_real.ini"):
        cfg = detect_and_parse((REPO / "samples" / fname).read_text())
        assert cfg.teams_interface().options_keepalive_interval == 120, fname


def test_inband_dtmf_on_teams_flagged(ruleset):
    """The Teams media stack does not support in-band DTMF -> flag it even if another
    leg uses RFC 2833 (so the general E.DTMF.METHOD check would stay quiet)."""
    from sbc_validator.models import NormalizedConfig, SipInterface
    from sbc_validator.validators.codec import CodecValidator
    cfg = NormalizedConfig(vendor="x", sip_interfaces=[
        SipInterface(name="T", role="teams", dtmf_method="inband"),
        SipInterface(name="C", role="carrier", dtmf_method="rfc2833")])
    assert "E.DTMF.INBAND_TEAMS" in ids(CodecValidator(ruleset).validate(cfg).findings)


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


def _ha_node(*, root="DigiCert Global Root G2", srtp=True, introspectable=True):
    return NormalizedConfig(vendor="x", sip_interfaces=[SipInterface(
        name="T", role="teams", transport="tls", srtp_enabled=srtp,
        tls_context=TlsContext(name="T", mtls_enabled=True,
                               trusted_root_ids=[root] if root else [],
                               introspectable=introspectable))])


def test_ha_trust_store_normalized_no_false_drift():
    # Same root named two ways across firmware must NOT read as trust-store drift.
    a, s = _ha_node(root="DigiCert Global Root G2"), _ha_node(root="DigiCertGlobalRootG2")
    assert "HA.DRIFT.TRUST_STORE" not in {f.check_id for f in ha_diff(a, s)}


def test_ha_trust_store_unverifiable_when_not_introspectable():
    # One node's store is imported separately: report LOW unverifiable, not a false
    # CRITICAL drift.
    found = {f.check_id: f.severity for f in
             ha_diff(_ha_node(root=None, introspectable=False), _ha_node())}
    assert found.get("HA.DRIFT.TRUST_STORE_UNVERIFIABLE") == Severity.LOW
    assert "HA.DRIFT.TRUST_STORE" not in found


def test_ha_srtp_drift_is_high():
    found = {f.check_id: f.severity for f in ha_diff(_ha_node(srtp=True), _ha_node(srtp=False))}
    assert found.get("HA.DRIFT.SRTP") == Severity.HIGH


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


def test_sim_expired_cert_dies_at_tls(ruleset):
    # An already-expired leaf must hard-stop the TLS handshake, not predict STABLE.
    # (Everything else in this config is healthy; only the cert is expired.)
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
                    ekus=[EKU.SERVER_AUTH], not_after="2020-01-01", chain_complete=True)))],
        media_realms=[MediaRealm(name="m", advertised_public_ip="80.0.0.5", symmetric_rtp=True)])
    findings = _all_findings(cfg, ruleset)
    assert any(f.check_id == "C.CERT.EXPIRY" and f.severity == Severity.CRITICAL
               for f in findings)
    sim = simulate_call(cfg, ruleset, findings)
    assert sim.outcome == "NO_CONNECT"
    assert sim.dies_at == "TLS handshake"
    # ladder truncates at the handshake; it never reaches INVITE
    assert not any("INVITE" in line for line in sim.ladder)


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


def test_pcap_sll2_linktype_supported():
    # `tcpdump -i any` on modern Linux writes LINKTYPE_LINUX_SLL2 (276); the reader
    # must strip its 20-byte header (protocol in the first 2 bytes) and yield the IP.
    import struct
    from sbc_validator.pcap import _parse_link, LINKTYPE_LINUX_SLL2
    ip = bytes([0x45, 0, 0, 20]) + b"\x00" * 16            # minimal IPv4 header
    sll2 = struct.pack(">H", 0x0800) + b"\x00" * 18 + ip   # 20-byte SLL2 header + IP
    assert _parse_link(LINKTYPE_LINUX_SLL2, sll2) == ip


def test_pcap_ipv4_non_first_fragment_skipped():
    # A non-first fragment carries no L4 header; parsing it as UDP/TCP is garbage.
    import struct
    from sbc_validator.pcap import _parse_ip
    hdr = bytearray(20)
    hdr[0] = 0x45
    hdr[2:4] = struct.pack(">H", 40)
    hdr[9] = 17                                            # UDP
    hdr[6:8] = struct.pack(">H", 0x0001)                  # fragment offset = 1 -> skip
    assert _parse_ip(bytes(hdr) + b"\x00" * 20) is None
    hdr[6:8] = struct.pack(">H", 0x2000)                  # MF set, offset 0 -> first frag
    assert _parse_ip(bytes(hdr) + b"\x00" * 20) is not None


def test_sip_487_caller_cancel_not_a_config_fault():
    # A caller hanging up before answer (INVITE/CANCEL/487) is not a transport fault.
    from sbc_validator.sip_trace import _RESPONSE_CAUSE
    assert _RESPONSE_CAUSE["487"][0] == "ok"
    assert _RESPONSE_CAUSE["491"][0] == "ok"


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


def test_tls_close_notify_not_flagged_as_handshake_failure():
    # A graceful TLS shutdown sends content-type 0x15 too. Only a FATAL alert is a
    # handshake failure; a warning-level close_notify must NOT be flagged.
    from sbc_validator.sip_trace import _fatal_tls_alert
    from sbc_validator.pcap import Packet

    def tcp5061(payload):
        return Packet(ts=0.0, proto="tcp", src_ip="a", dst_ip="b",
                      src_port=5061, dst_port=40000, payload=payload)

    # warning-level (1) close_notify (desc 0) -> clean shutdown, not a failure
    assert _fatal_tls_alert(tcp5061(bytes([0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00]))) is None
    # fatal (2) unknown_ca (desc 48) -> a genuine handshake failure
    assert _fatal_tls_alert(tcp5061(bytes([0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 48]))) == 48
    # application-data record (0x17) is not an alert
    assert _fatal_tls_alert(tcp5061(bytes([0x17, 0x03, 0x03, 0x01, 0x00]) + b"x" * 20)) is None
    # an alert off the SIP/TLS port is ignored
    off = Packet(0.0, "tcp", "a", "b", 443, 40000, bytes([0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 48]))
    assert _fatal_tls_alert(off) is None


def test_rtcp_not_counted_as_rtp_media():
    # RTCP often returns even when RTP media does not; counting it as media would
    # mask genuine one-way audio. Per RFC 5761 the second byte (200-204) is RTCP.
    from sbc_validator.sip_trace import _looks_rtp
    from sbc_validator.pcap import Packet

    def udp(payload):
        return Packet(0.0, "udp", "a", "b", 50000, 6000, payload)

    assert _looks_rtp(udp(bytes([0x80, 0x00]) + b"\x00" * 20)) is True    # RTP PT 0 (PCMU)
    assert _looks_rtp(udp(bytes([0x80, 200]) + b"\x00" * 20)) is False    # RTCP sender report


# ---- SRTP media-encryption check (domain C) --------------------------------

def test_c_flags_missing_srtp(ruleset):
    cfg = detect_and_parse((REPO / "samples" / "audiocodes_min.ini").read_text())
    res = CaComplianceValidator(ruleset).validate(cfg)
    assert "C.SRTP.DISABLED" in ids(res.findings)


def test_c_no_srtp_finding_when_enabled(ruleset):
    cfg = detect_and_parse((REPO / "samples" / "clean_pass.ini").read_text())
    res = CaComplianceValidator(ruleset).validate(cfg)
    assert "C.SRTP.DISABLED" not in ids(res.findings)


def test_tristate_unknown_fields_stay_silent(ruleset):
    # A config that does not carry SRTP / keep-alive / mTLS / symmetric-RTP / chain
    # info (all left None) must NOT produce false 'disabled'/'incomplete' findings:
    # unknown is not 'off'. This is 'silence beats a wrong verdict' at the model
    # level, and the exact false-positive class a real .ini would otherwise hit.
    from sbc_validator.validators.interop import InteropValidator
    root_names = [r["name"] for r in ruleset["C"]["required_root_ca_ids"]]
    cfg = NormalizedConfig(
        vendor="x", sbc_fqdn="sbc.example.com",
        sip_interfaces=[SipInterface(
            name="T", role="teams", fqdn="sbc.example.com", transport="tls",
            offered_codecs=["PCMU", "G722"],
            # srtp_enabled / options_keepalive deliberately left as None (unknown)
            tls_context=TlsContext(
                name="T", trusted_root_ids=list(root_names),     # mtls_enabled None
                presented_cert=Certificate(
                    subject_cn="sbc.example.com", sans=["sbc.example.com"],
                    ekus=[EKU.SERVER_AUTH], not_after="2030-01-01")))],  # chain_complete None
        media_realms=[MediaRealm(name="m", advertised_public_ip="80.0.0.5")])  # symmetric_rtp None
    c = ids(CaComplianceValidator(ruleset).validate(cfg).findings)
    b = ids(InteropValidator(ruleset).validate(cfg).findings)
    d = ids(NatTraversalValidator(ruleset).validate(cfg).findings)
    assert "C.SRTP.DISABLED" not in c
    assert "C.TLS.MTLS_DISABLED" not in c
    assert "C.CERT.CHAIN_INCOMPLETE" not in c
    assert "B.SIP.OPTIONS_KEEPALIVE" not in b
    assert "D.NAT.NO_SYMMETRIC_RTP" not in d


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


def test_nat_internal_realm_private_ip_not_blocked(ruleset):
    # An internal/LAN realm legitimately uses a private address; judging it as a
    # public-advertisement fault would be a false CRITICAL/BLOCK on a correct
    # two-realm topology. Public realm with a private advertised IP still fires.
    cfg = NormalizedConfig(vendor="x", media_realms=[
        MediaRealm(name="internal", advertised_public_ip="10.50.0.7",
                   symmetric_rtp=True, role="internal"),
        MediaRealm(name="teams", advertised_public_ip="80.0.0.9",
                   symmetric_rtp=True, role="teams"),
    ])
    found = ids(NatTraversalValidator(ruleset).validate(cfg).findings)
    assert "D.NAT.PRIVATE_ADVERTISED" not in found     # internal realm not flagged

    bad = NormalizedConfig(vendor="x", media_realms=[
        MediaRealm(name="teams", advertised_public_ip="10.50.0.7",
                   symmetric_rtp=True, role="teams")])
    assert "D.NAT.PRIVATE_ADVERTISED" in ids(NatTraversalValidator(ruleset).validate(bad).findings)


def test_nat_public_local_ip_needs_no_advertisement(ruleset):
    # A realm bound to a globally-routable interface needs no separate NAT
    # advertisement; absence of advertised_public_ip must NOT be a false HIGH.
    cfg = NormalizedConfig(vendor="x", media_realms=[
        MediaRealm(name="dmz", advertised_public_ip=None, local_ip="80.0.0.20",
                   symmetric_rtp=True, role="teams")])
    assert "D.NAT.NO_PUBLIC_IP" not in ids(NatTraversalValidator(ruleset).validate(cfg).findings)


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


def test_remote_fetch_verifies_and_caches(tmp_path):
    """Remote transport: a signed bundle from the API is verified, then cached."""
    raw = RULESET.read_bytes()
    client = RuleClient(api_base="https://rules.example", cache_dir=tmp_path,
                        fetcher=lambda url: raw)
    bundle = client.fetch("ms_direct_routing")
    assert bundle["bundle_version"] == "2026-06-07"
    assert (tmp_path / "ms_direct_routing.json").exists()    # cached for offline reuse


def test_remote_fetch_rejects_tampered(tmp_path):
    bundle = json.loads(RULESET.read_text())
    bundle["C"]["cert_expiry_warn_days"] = 9999              # tamper after signing
    tampered = json.dumps(bundle).encode()
    client = RuleClient(api_base="https://rules.example", cache_dir=tmp_path,
                        fetcher=lambda url: tampered)
    with pytest.raises(RuleVerificationError):
        client.fetch("ms_direct_routing")


def test_remote_fetch_falls_back_to_cache_on_network_error(tmp_path):
    # seed the cache with a verified bundle
    RuleClient(cache_dir=tmp_path).fetch("ms_direct_routing", local_path=str(RULESET))

    def boom(url):
        raise OSError("network down")

    client = RuleClient(api_base="https://rules.example", cache_dir=tmp_path, fetcher=boom)
    bundle = client.fetch("ms_direct_routing")               # network fails -> cache
    assert bundle["bundle_version"] == "2026-06-07"
    assert any("cache" in w for w in bundle.get("_warnings", []))


def test_resign_roundtrip(tmp_path, signing_key):
    bundle = json.loads(RULESET.read_text())
    bundle.pop("signature")
    bundle["C"]["cert_expiry_warn_days"] = 45
    resigned = sign_bundle(bundle, signing_key)
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


def test_c_empty_introspectable_trust_store_is_critical(ruleset):
    # The source authoritatively enumerates the trust store (introspectable=True)
    # and it is empty -> a total gap, a guaranteed mTLS hard-stop in the 2026
    # rotation. Must be CRITICAL C.CA.ROOT_MISSING, not a LOW "verify out-of-band".
    cfg = NormalizedConfig(
        vendor="x", sbc_fqdn="sbc.example.com",
        sip_interfaces=[SipInterface(
            name="T", role="teams", fqdn="sbc.example.com",
            tls_context=TlsContext(
                name="T", mtls_enabled=True, trusted_root_ids=[], introspectable=True,
                presented_cert=Certificate(
                    subject_cn="sbc.example.com", sans=["sbc.example.com"],
                    ekus=[EKU.SERVER_AUTH], not_after="2030-01-01", chain_complete=True),
            ))])
    res = CaComplianceValidator(ruleset).validate(cfg)
    found = {f.check_id: f.severity for f in res.findings}
    assert found.get("C.CA.ROOT_MISSING") == Severity.CRITICAL
    assert "C.CA.TRUST_STORE_UNAVAILABLE" not in found


def test_c_empty_non_introspectable_trust_store_is_low(ruleset):
    # Same empty trust store, but the source does NOT authoritatively enumerate it
    # (e.g. an AudioCodes .ini): must stay LOW "verify out-of-band", never CRITICAL.
    cfg = NormalizedConfig(
        vendor="x", sbc_fqdn="sbc.example.com",
        sip_interfaces=[SipInterface(
            name="T", role="teams", fqdn="sbc.example.com",
            tls_context=TlsContext(
                name="T", mtls_enabled=True, trusted_root_ids=[], introspectable=False,
                presented_cert=Certificate(
                    subject_cn="sbc.example.com", sans=["sbc.example.com"],
                    ekus=[EKU.SERVER_AUTH], not_after="2030-01-01", chain_complete=True),
            ))])
    res = CaComplianceValidator(ruleset).validate(cfg)
    found = ids(res.findings)
    assert "C.CA.TRUST_STORE_UNAVAILABLE" in found
    assert "C.CA.ROOT_MISSING" not in found


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


def test_dtmf_mixed_and_nonpreferred_still_flags_inconsistent(ruleset):
    # {inband, info}: both non-preferred AND mixed. The worse config must still get
    # the MEDIUM inconsistency finding; an elif previously let it escape with only a
    # LOW, scoring the worse config lower.
    cfg = NormalizedConfig(vendor="x", sip_interfaces=[
        SipInterface(name="T", role="teams", dtmf_method="inband", offered_codecs=["PCMU"]),
        SipInterface(name="C", role="carrier", dtmf_method="info", offered_codecs=["PCMU"]),
    ])
    got = {f.check_id for f in CodecValidator(ruleset).validate(cfg).findings}
    assert "E.DTMF.INCONSISTENT" in got


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


def test_verify_chain_handles_cross_signed_sibling(tmp_path):
    # Two intermediates share a subject (cross-sign), but only one actually signed
    # the leaf. Keying the issuer by subject as a single cert could pick the decoy
    # and false-flag CHAIN_INVALID / UNTRUSTED_ANCHOR. verify_chain must pick the
    # real signer and still reach the root. (The DigiCert G5 / MS 2017 reality.)
    if not cert_inspect.available():
        pytest.skip("cryptography not installed")
    import datetime
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    def key():
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def nm(cn):
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])

    t0 = datetime.datetime(2026, 1, 1)
    t1 = t0 + datetime.timedelta(days=3650)

    def ca(subject, issuer_name, issuer_key, subj_key):
        return (x509.CertificateBuilder().subject_name(nm(subject))
                .issuer_name(issuer_name).public_key(subj_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(t0).not_valid_after(t1)
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
                .sign(issuer_key, hashes.SHA256()))

    rk, real_k, decoy_k, lk = key(), key(), key(), key()
    root = ca("XSign Root", nm("XSign Root"), rk, rk)
    inter_real = ca("XSign Inter", root.subject, rk, real_k)
    inter_decoy = ca("XSign Inter", root.subject, rk, decoy_k)   # same subject, other key
    leaf = (x509.CertificateBuilder().subject_name(nm("sbc.example.com"))
            .issuer_name(inter_real.subject).public_key(lk.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(t0).not_valid_after(t0 + datetime.timedelta(days=365))
            .sign(real_k, hashes.SHA256()))

    def pem(c):
        return c.public_bytes(serialization.Encoding.PEM)

    # decoy listed AFTER the real signer: a last-wins subject map would pick it.
    blob = pem(leaf) + pem(inter_real) + pem(inter_decoy) + pem(root)
    p = tmp_path / "xsigned.pem"
    p.write_bytes(blob)
    r = cert_inspect.verify_chain(str(p))
    assert r["reached_root"] is True
    assert r["signatures_valid"] is True


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


# ---- fleet readiness report ------------------------------------------------

def test_fleet_rollup_and_markdown(ruleset):
    import glob, os
    from sbc_validator.fleet import run_fleet, render_markdown
    paths = sorted(p for p in glob.glob(str(REPO / "samples" / "*")) if os.path.isfile(p))
    result = run_fleet(paths, ruleset)
    assert result["total"] >= 6
    assert result["ca_2026_not_ready"] >= 1            # some configs carry CA/cert blockers
    assert result["ca_2026_ready"] + result["ca_2026_not_ready"] == result["total"]
    assert sum(result["verdicts"].values()) == result["total"]
    md = render_markdown(result)
    assert "SBC Fleet Readiness Report" in md
    assert "2026 Microsoft CA migration readiness" in md


def test_fleet_cli_gates_on_not_ready():
    # samples/ contains configs that aren't 2026-ready -> fleet exits non-zero
    rc = _cli_main(["fleet", str(REPO / "samples"), "--ruleset", _R, "--json"])
    assert rc == 1


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


# ---- hardening: trust-boundary + input safety (first-principles sweep) ------

def test_rollback_signed_but_stale_rejected(tmp_path, signing_key):
    """A validly-signed but OLDER bundle must be refused (freshness != authenticity).

    This is the deepest gap: the pre-2026-06-07 CA list is still a valid
    signature, so without a version floor the tool would happily screen against
    a retired-root list. Seed the cache with the current bundle, then offer a
    correctly re-signed older one and expect a hard refusal.
    """
    def mk(version):  # minimal validly-signed bundle at a given version
        return sign_bundle(
            {"ruleset_id": "ms_direct_routing", "bundle_version": version, "C": {}},
            signing_key,
        )

    client = RuleClient(cache_dir=tmp_path)
    cur = tmp_path / "cur.json"
    cur.write_text(json.dumps(mk("2026-06-07")))
    client.fetch("ms_direct_routing", local_path=str(cur))          # caches 2026-06-07

    old = tmp_path / "old.json"
    old.write_text(json.dumps(mk("2026-06-06")))

    # Even a clean install (no cache, env unset) refuses the stale bundle: the
    # compiled-in _MIN_BUNDLE_VERSION floor means freshness no longer depends on a
    # seeded cache, closing the clean-first-run rollback window.
    _clean = RuleClient(cache_dir=tmp_path / "empty")
    with pytest.raises(RuleVerificationError):
        _clean.fetch("ms_direct_routing", local_path=str(old))
    with pytest.raises(RuleVerificationError):
        client.fetch("ms_direct_routing", local_path=str(old))      # also rolled back vs. cache


def test_env_min_version_floor(tmp_path, monkeypatch):
    monkeypatch.setenv("SBC_RULE_MIN_VERSION", "2027-01-01")
    with pytest.raises(RuleVerificationError):
        RuleClient(cache_dir=tmp_path).fetch("ms_direct_routing", local_path=str(RULESET))


def test_cache_fallback_enforces_freshness_floor(tmp_path, signing_key):
    # The locally-writable cache must not be a rollback vector: a downgraded but
    # validly-signed cache file (older than the compiled-in floor) is refused on the
    # network-failure fallback path, not served as-is.
    def mk(version):
        return sign_bundle(
            {"ruleset_id": "ms_direct_routing", "bundle_version": version, "C": {}},
            signing_key,
        )

    cache = tmp_path / "ms_direct_routing.json"
    cache.write_text(json.dumps(mk("2026-06-05")))      # stale, but validly signed

    def boom(url):
        raise OSError("network down")

    client = RuleClient(api_base="https://rules.example", cache_dir=tmp_path, fetcher=boom)
    with pytest.raises(RuleVerificationError):
        client.fetch("ms_direct_routing")               # network fails -> cache -> floor refuses


def test_non_https_transport_refused():
    with pytest.raises(RuleVerificationError):
        RuleClient(api_base="http://rules.example")._http_get("http://rules.example/x")
    with pytest.raises(RuleVerificationError):
        RuleClient()._http_get("file:///etc/passwd")


def test_non_dict_bundle_rejected_cleanly(tmp_path):
    # A ruleset file that is valid JSON but not an object (e.g. a list) must raise a
    # clean RuleVerificationError, not an AttributeError traceback in front of a user.
    p = tmp_path / "bad.json"
    p.write_text("[1, 2, 3]")
    with pytest.raises(RuleVerificationError):
        RuleClient(cache_dir=tmp_path).fetch("ms_direct_routing", local_path=str(p))


def test_runtime_dependencies_stay_minimal():
    # The single-runtime-dependency rule (only `cryptography`) is a real
    # differentiator for a local-first, air-gapped, supply-chain-averse tool. This
    # ratchet fails if a runtime dep is added; update it deliberately when you mean to.
    import re
    text = (REPO / "pyproject.toml").read_text()
    block = re.search(r"^dependencies\s*=\s*\[(.*?)\]", text, re.S | re.M).group(1)
    names = [re.split(r"[><=!~ ]", d.strip().strip('"').strip("'"))[0]
             for d in block.split(",") if d.strip()]
    assert names == ["cryptography"], f"runtime dependencies drifted: {names}"


def test_python_dash_m_entrypoint():
    # `python -m sbc_validator --help` must work (the __main__.py alias), so the
    # package is runnable without the console script being on PATH.
    import subprocess, sys
    r = subprocess.run([sys.executable, "-m", "sbc_validator", "--help"],
                       capture_output=True, text=True, cwd=str(REPO))
    assert r.returncode == 0 and "validate" in r.stdout


_WALK = REPO / "samples" / "walkthrough"


def test_walkthrough_pair_broken_blocks_fixed_passes(ruleset):
    # The golden-path pair: the SAME SBC, broken -> BLOCK, fixed -> PASS. This is the
    # "close the loop" proof the end-to-end walkthrough is built on.
    broken = detect_and_parse((_WALK / "sbc-teams-01-broken.ini").read_text())
    fixed = detect_and_parse((_WALK / "sbc-teams-01-fixed.ini").read_text())
    assert score(_all_findings(broken, ruleset))["verdict"] == "BLOCK"
    assert score(_all_findings(fixed, ruleset))["verdict"] == "PASS"


def test_walk_command_runs_end_to_end():
    # `walk` narrates the whole pipeline and exits cleanly on the broken sample.
    import subprocess, sys
    r = subprocess.run([sys.executable, "-m", "sbc_validator", "walk",
                        "samples/walkthrough/sbc-teams-01-broken.ini"],
                       capture_output=True, text=True, cwd=str(REPO))
    assert r.returncode == 0
    out = r.stdout
    assert "STAGE 1 — INGEST" in out
    assert "VERDICT: BLOCK" in out
    assert "NO_CONNECT" in out


def test_unsafe_ruleset_id_rejected(tmp_path):
    with pytest.raises(RuleVerificationError):
        RuleClient(cache_dir=tmp_path)._cache_path("../escape")


def test_pcap_rejects_oversized(monkeypatch):
    from sbc_validator import pcap
    monkeypatch.setattr(pcap, "_MAX_PCAP_BYTES", 10)
    with pytest.raises(ValueError):
        pcap.read_packets(str(REPO / "samples" / "clean_call.pcap"))


def test_cli_malformed_config_clean_exit(tmp_path):
    from sbc_validator.cli import main
    bad = tmp_path / "bad.ini"
    bad.write_text("@@@ not any known vendor format @@@")
    with pytest.raises(SystemExit) as ei:
        main(["validate", str(bad), "--ruleset", str(RULESET)])
    assert ei.value.code == 2


def test_demo_runs_and_writes_results(tmp_path):
    """The packaged showcase runs end-to-end and records per-SBC results."""
    from sbc_validator.cli import main
    out = tmp_path / "out"
    rc = main(["demo", "--samples", str(REPO / "samples"),
               "--ruleset", str(RULESET), "--out", str(out)])
    assert rc == 0
    results = list(out.glob("*/*.json"))
    assert len(results) >= 4          # four-vendor fleet recorded


def test_cli_tampered_ruleset_clean_exit(tmp_path):
    """A tampered/invalid ruleset must be refused with a clean exit, not a traceback."""
    from sbc_validator.cli import main
    bundle = json.loads(RULESET.read_text())
    bundle["C"]["cert_expiry_warn_days"] = 9999      # breaks the signature
    p = tmp_path / "tampered.json"
    p.write_text(json.dumps(bundle))
    with pytest.raises(SystemExit) as ei:
        main(["validate", str(SAMPLE), "--ruleset", str(p)])
    assert ei.value.code == 2


def test_validate_autodiscovers_ruleset(monkeypatch):
    """--ruleset is optional: the shipped bundle is found relative to CWD."""
    from sbc_validator.cli import main
    monkeypatch.chdir(REPO)
    rc = main(["validate", str(SAMPLE)])     # no --ruleset; audiocodes_min -> BLOCK
    assert rc == 1


# ---- domain S: security / access-control (B2BUA carrier-leg perimeter) ------

def test_access_control_flags_exposure():
    from sbc_validator.models import NormalizedConfig, AccessControlEntry as ACE
    from sbc_validator.validators.access_control import AccessControlValidator
    cfg = NormalizedConfig(
        vendor="x",
        access_controls=[ACE(plane="signaling", ip_version=4, action="permit",
                             cidr="198.51.0.0/16")],   # broad, signaling-only, ipv4-only, no deny
        rtp_source_validation=False,
    )
    got = {f.check_id for f in AccessControlValidator({}).validate(cfg).findings}
    assert {"S.ACL.NO_DEFAULT_DENY", "S.ACL.BROAD_CIDR", "S.ACL.MEDIA_PLANE_MISSING",
            "S.ACL.IPV6_NEGLECT", "S.RTP.SOURCE_VALIDATION_OFF"} <= got


def test_access_control_silent_without_acl_info():
    from sbc_validator.models import NormalizedConfig
    from sbc_validator.validators.access_control import AccessControlValidator
    cfg = NormalizedConfig(vendor="x")            # no ACL info -> say nothing
    assert AccessControlValidator({}).validate(cfg).findings == []


def test_codec_wideband_downgrade(ruleset):
    cfg = detect_and_parse((REPO / "samples" / "cisco_cube_dr.txt").read_text())
    res = CodecValidator(ruleset).validate(cfg)   # teams wideband G722, common only PCMU
    assert "E.CODEC.WIDEBAND_DOWNGRADE" in ids(res.findings)


def test_carrier_leg_keepalive_advisory(ruleset):
    absent = detect_and_parse((REPO / "samples" / "oracle_teams.acli").read_text())
    assert "B.SIP.CARRIER_NO_KEEPALIVE" in ids(InteropValidator(ruleset).validate(absent).findings)
    present = detect_and_parse((REPO / "samples" / "clean_pass.ini").read_text())
    assert "B.SIP.CARRIER_NO_KEEPALIVE" not in ids(InteropValidator(ruleset).validate(present).findings)


def test_audiocodes_acl_extracted_secure_posture():
    """Domain S now fires through the real AudioCodes AccessList table (clean case)."""
    from sbc_validator.validators.access_control import AccessControlValidator
    cfg = detect_and_parse((REPO / "samples" / "audiocodes_teams_real.ini").read_text())
    assert len(cfg.access_controls) >= 4          # default-deny + carrier allow-list
    assert AccessControlValidator({}).validate(cfg).findings == []   # secure -> silent


def test_audiocodes_exposed_acl_fires_domain_s():
    from sbc_validator.validators.access_control import AccessControlValidator
    cfg = detect_and_parse((REPO / "samples" / "audiocodes_exposed.ini").read_text())
    got = {f.check_id for f in AccessControlValidator({}).validate(cfg).findings}
    assert {"S.ACL.NO_DEFAULT_DENY", "S.ACL.BROAD_CIDR",
            "S.ACL.MEDIA_PLANE_MISSING", "S.ACL.IPV6_NEGLECT"} <= got


def test_acl_shadowed_deny_is_high():
    # A broad permit above a specific deny: the deny is dead (first-match, top-down),
    # so the host meant to be blocked is admitted. Security hole -> HIGH.
    from sbc_validator.models import NormalizedConfig, AccessControlEntry as ACE
    from sbc_validator.validators.access_control import AccessControlValidator
    cfg = NormalizedConfig(vendor="x", access_controls=[
        ACE(plane="both", ip_version=4, action="permit", cidr="198.51.100.0/24"),
        ACE(plane="both", ip_version=4, action="deny", cidr="198.51.100.66/32"),  # shadowed
        ACE(plane="both", ip_version=4, action="deny", cidr="0.0.0.0/0"),
    ])
    got = {f.check_id: f.severity for f in AccessControlValidator({}).validate(cfg).findings}
    assert got.get("S.ACL.SHADOWED_DENY") == Severity.HIGH


def test_acl_shadowed_permit_is_medium():
    # A broad deny above a specific permit: the permit is dead, the peer you meant
    # to allow is blocked (trunk down). Availability problem -> MEDIUM.
    from sbc_validator.models import NormalizedConfig, AccessControlEntry as ACE
    from sbc_validator.validators.access_control import AccessControlValidator
    cfg = NormalizedConfig(vendor="x", access_controls=[
        ACE(plane="both", ip_version=4, action="deny", cidr="203.0.113.0/24"),
        ACE(plane="both", ip_version=4, action="permit", cidr="203.0.113.10/32"),  # shadowed
    ])
    got = {f.check_id: f.severity for f in AccessControlValidator({}).validate(cfg).findings}
    assert got.get("S.ACL.SHADOWED_PERMIT") == Severity.MEDIUM


def test_acl_correct_order_no_shadowing():
    # Specific rules above the broad catch-all: nothing is shadowed.
    from sbc_validator.models import NormalizedConfig, AccessControlEntry as ACE
    from sbc_validator.validators.access_control import AccessControlValidator
    cfg = NormalizedConfig(vendor="x", access_controls=[
        ACE(plane="both", ip_version=4, action="deny", cidr="198.51.100.66/32"),
        ACE(plane="both", ip_version=4, action="permit", cidr="198.51.100.0/24"),
        ACE(plane="both", ip_version=4, action="deny", cidr="0.0.0.0/0"),
    ])
    got = {f.check_id for f in AccessControlValidator({}).validate(cfg).findings}
    assert "S.ACL.SHADOWED_DENY" not in got and "S.ACL.SHADOWED_PERMIT" not in got


def test_wildcard_cert_fqdn_match():
    """MS Direct Routing supports wildcard certs; exact-match would false-flag."""
    from sbc_validator.validators.ca_compliance import _name_covers, _fqdn_matches
    assert _name_covers("*.adatum.biz", "sbc1.adatum.biz")        # one label -> match
    assert not _name_covers("*.adatum.biz", "a.b.adatum.biz")     # two labels -> no
    assert not _name_covers("*.adatum.biz", "adatum.biz")         # bare domain -> no
    assert _name_covers("sbc1.adatum.biz", "sbc1.adatum.biz")     # exact
    assert _fqdn_matches("sbc1.adatum.biz", ["*.adatum.biz"])     # via SAN wildcard


def test_wildcard_cert_no_false_fqdn_mismatch(ruleset):
    """A wildcard leaf covering the SBC FQDN must NOT raise C.CERT.FQDN_MISMATCH."""
    from sbc_validator.models import NormalizedConfig, SipInterface, TlsContext, Certificate, EKU
    leaf = Certificate(subject_cn="*.contoso.com", sans=["*.contoso.com"],
                       ekus=[EKU.SERVER_AUTH], not_after="2027-01-01",
                       chain_complete=True, source_file="x.pem")
    ctx = TlsContext(name="t", mtls_enabled=True, presented_cert=leaf,
                     trusted_root_ids=[], introspectable=True)
    cfg = NormalizedConfig(vendor="x", sbc_fqdn="sbc1.contoso.com",
                           sip_interfaces=[SipInterface(name="Teams", role="teams",
                                           fqdn="sbc1.contoso.com", tls_context=ctx,
                                           transport="tls")])
    ids_found = {f.check_id for f in CaComplianceValidator(ruleset).validate(cfg).findings}
    assert "C.CERT.FQDN_MISMATCH" not in ids_found


def test_ip_identity_flagged(ruleset):
    """An IP (not FQDN) as the SBC identity is a 403 risk (MS DR SIP spec)."""
    from sbc_validator.models import NormalizedConfig, SipInterface
    ipcfg = NormalizedConfig(vendor="x", sbc_fqdn="203.0.113.9",
                             sip_interfaces=[SipInterface(name="Teams", role="teams",
                                             transport="tls", options_keepalive=True)])
    got = {f.check_id for f in InteropValidator(ruleset).validate(ipcfg).findings}
    assert "B.SIP.IDENTITY_IS_IP" in got
    # an FQDN identity must NOT trip it
    ok = detect_and_parse((REPO / "samples" / "clean_pass.ini").read_text())
    assert "B.SIP.IDENTITY_IS_IP" not in {f.check_id for f in InteropValidator(ruleset).validate(ok).findings}


def test_report_command(tmp_path):
    """The executive report renders from a results dir (Markdown + HTML)."""
    from sbc_validator.cli import main
    out = tmp_path / "res"
    assert main(["demo", "--samples", str(REPO / "samples"),
                 "--ruleset", str(RULESET), "--out", str(out)]) == 0
    assert main(["report", "--results", str(out)]) == 0           # markdown to stdout
    html = tmp_path / "exec.html"
    assert main(["report", "--results", str(out), "--out", str(html)]) == 0
    h = html.read_text()
    assert "Executive Report" in h and "CA migration" in h and "access-control" in h
