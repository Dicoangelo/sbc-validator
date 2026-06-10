"""Acceptance tests for the 'install a control' compliance report (B8).

The report maps fleet findings to regulatory control families and is
integrity-protected by a SHA-256 content hash (NOT a cryptographic signature).
"""
from sbc_validator.report import compliance


def _payload():
    """Minimal fleet payload in the shape build_dashboard_data emits."""
    return {
        "generated_at": "2026-06-10T00:00:00+00:00",
        "ruleset_version": "2026.06.0",
        "fleet": [
            {
                "sbc": "sbc-a", "vendor": "audiocodes", "site": "nyc",
                "ruleset_version": "2026.06.0",
                "summary": {"verdict": "BLOCK", "risk_score": 80},
                "findings": [
                    {"check_id": "C.TLS.FLOOR_BELOW_1_2", "severity": "HIGH"},
                    {"check_id": "B.SIP.OPTIONS_INTERVAL", "severity": "MEDIUM"},
                ],
            },
            {
                "sbc": "sbc-b", "vendor": "cisco_cube", "site": "ldn",
                "ruleset_version": "2026.06.0",
                "summary": {"verdict": "PASS", "risk_score": 0},
                "findings": [],
            },
        ],
    }


def test_frameworks_listed():
    fws = compliance.frameworks()
    assert fws == ["cjis", "finra", "hipaa", "mifid2"]


def test_render_maps_findings_to_families():
    md = compliance.render_markdown(_payload(), "mifid2")
    # framework title + verdict table + both SBCs present
    assert "MiFID II" in md
    assert "| sbc-a | audiocodes | BLOCK | 80 |" in md
    assert "| sbc-b | cisco_cube | PASS | 0 |" in md
    # TLS finding lands in recording-continuity; SIP finding in availability
    assert "C.TLS.FLOOR_BELOW_1_2" in md
    assert "B.SIP.OPTIONS_INTERVAL" in md
    # ruleset stamp + honesty disclaimer present
    assert "2026.06.0" in md
    assert "not legal advice" in md
    assert "NOT cryptographically\nsigned" in md or "not claim the report" in md \
        or "signs rulesets only" in md


def test_silent_family_is_not_certified():
    # access-control (S.) has no findings -> must read as absence, not pass
    md = compliance.render_markdown(_payload(), "hipaa")
    assert "No open findings in this family" in md
    assert "not a certification" in md


def test_content_hash_round_trips():
    md = compliance.render_markdown(_payload(), "finra")
    assert compliance.verify_markdown(md) is True


def test_tamper_is_detected():
    md = compliance.render_markdown(_payload(), "cjis")
    tampered = md.replace("BLOCK", "PASS", 1)
    assert compliance.verify_markdown(tampered) is False


def test_hash_invariant_to_trailing_newlines():
    # A forwarded report often gains/loses trailing newlines (print, shells,
    # editors). The content hash must survive that without false tamper alarms.
    md = compliance.render_markdown(_payload(), "mifid2")
    assert compliance.verify_markdown(md + "\n\n") is True
    assert compliance.verify_markdown(md.rstrip("\n")) is True


def test_html_wraps_and_escapes():
    html = compliance.render_html(_payload(), "mifid2")
    assert html.startswith("<!doctype html>")
    assert "<pre>" in html
    # markdown angle-free content escaped; no raw script injection surface
    assert "MiFID II" in html


def test_all_frameworks_render():
    p = _payload()
    for fw in compliance.frameworks():
        md = compliance.render_markdown(p, fw)
        assert compliance.verify_markdown(md) is True
