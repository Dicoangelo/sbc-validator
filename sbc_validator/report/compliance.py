"""
"Install a control" compliance report.

Maps the fleet's findings to the control families a regulated buyer's
change-management procedure cares about (MiFID II, FINRA, CJIS, HIPAA), so
SBC-AutoOps can be NAMED as the pre-deploy step in an audited procedure.

Honesty contract (stated in the report itself):
  * The mapping is indicative, not legal advice.
  * Rule FACTS are Ed25519-signed (the bundle); the report's own integrity is a
    SHA-256 content hash printed in the footer — we do not claim the report is
    cryptographically signed (the publisher's private key lives offline and
    signs rulesets, not reports).
  * Findings reflect what the supplied config sources can prove; silent domains
    are listed as "not assessable from source", never as satisfied.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone

# framework -> ordered control families. Each family: (key, title, what it means
# for voice, finding check-id prefixes that evidence it).
_FRAMEWORKS: dict[str, dict] = {
    "mifid2": {
        "name": "MiFID II (RTS 25 / Art. 16(7) recording continuity)",
        "families": [
            ("recording-continuity", "Call-recording continuity",
             "A TLS/CA/SRTP blocker silently stops recorded trader voice; the "
             "regulated firm must prove changes cannot break recording.",
             ("C.CA.", "C.CERT.", "C.TLS.", "C.SRTP")),
            ("availability", "Trunk availability / silent-failure prevention",
             "OPTIONS keep-alive and transport posture prevent the silent "
             "deactivation class of outage.",
             ("B.SIP.",)),
            ("media-integrity", "Media path integrity",
             "NAT/media posture that produces one-way audio degrades recorded "
             "evidence without an outage alarm.",
             ("D.",)),
            ("access-control", "Perimeter access control",
             "Signaling/media plane exposure of the recording estate.",
             ("S.",)),
        ],
    },
    "finra": {
        "name": "FINRA (books-and-records / supervision of communications)",
        "families": [
            ("recording-continuity", "Recorded-line continuity",
             "Cert/TLS blockers stop recorded lines without an error surface.",
             ("C.CA.", "C.CERT.", "C.TLS.", "C.SRTP")),
            ("change-evidence", "Change supervision evidence",
             "Each change carries a deterministic, ruleset-stamped verdict.",
             ()),
            ("access-control", "Access control", "Perimeter exposure.", ("S.",)),
        ],
    },
    "cjis": {
        "name": "CJIS Security Policy (encrypted transmission, access control)",
        "families": [
            ("encryption-in-transit", "Encryption in transit (signaling + media)",
             "TLS posture and SRTP enforcement on the voice path.",
             ("C.TLS.", "C.SRTP", "C.CERT.", "C.CA.")),
            ("media-exposure", "Media exposure", "NAT/media leak posture.", ("D.", "F.")),
            ("access-control", "Access enforcement", "ACL default-deny posture.", ("S.",)),
        ],
    },
    "hipaa": {
        "name": "HIPAA Security Rule (transmission security, access control)",
        "families": [
            ("transmission-security", "Transmission security",
             "Encryption posture of PHI-bearing voice (TLS/SRTP).",
             ("C.TLS.", "C.SRTP", "C.CERT.", "C.CA.")),
            ("media-exposure", "Media exposure", "One-way-audio/NAT posture.", ("D.",)),
            ("access-control", "Access control", "Perimeter ACLs.", ("S.",)),
        ],
    },
}

_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def frameworks() -> list[str]:
    return sorted(_FRAMEWORKS)


def _family_findings(payload: dict, prefixes) -> list[dict]:
    out = []
    for sbc in payload.get("fleet", []):
        for f in sbc.get("findings", []):
            cid = f.get("check_id", "")
            if any(cid.startswith(p) for p in prefixes):
                out.append({"sbc": sbc.get("sbc", "?"), "check_id": cid,
                            "severity": f.get("severity", "INFO")})
    return sorted(out, key=lambda x: _SEV_ORDER.get(x["severity"], 9))


def render_markdown(payload: dict, framework: str) -> str:
    fw = _FRAMEWORKS[framework]
    fleet = payload.get("fleet", [])
    rs_ver = (fleet[0].get("ruleset_version") if fleet else None) \
        or payload.get("ruleset_version", "unknown")
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    lines = [
        f"# SBC Pre-Deployment Compliance Report — {fw['name']}",
        "",
        f"_Generated {now} · ruleset {rs_ver} (Ed25519-signed bundle) · "
        f"{len(fleet)} SBC(s) assessed_",
        "",
        "**What this is:** the deterministic pre-deployment verdict for each SBC "
        "configuration, mapped to the control families above. It is designed to be "
        "retained as the change-record evidence when SBC-AutoOps is named as the "
        "pre-deploy control in an audited change-management procedure.",
        "",
        "**Mapping disclaimer:** indicative control mapping, not legal advice.",
        "",
        "## Verdicts",
        "",
        "| SBC | Vendor | Verdict | Risk |",
        "|---|---|---|---:|",
    ]
    for s in fleet:
        sm = s.get("summary", {})
        lines.append(f"| {s.get('sbc','?')} | {s.get('vendor','?')} | "
                     f"{sm.get('verdict','?')} | {sm.get('risk_score','?')} |")
    lines += ["", "## Control families", ""]
    for key, title, why, prefixes in fw["families"]:
        lines.append(f"### {title}")
        lines.append(f"_{why}_")
        if not prefixes:
            lines.append("- Evidence: this report itself (deterministic verdict, "
                         "ruleset-stamped, retained per change). No finding class "
                         "maps here.")
            lines.append("")
            continue
        hits = _family_findings(payload, prefixes)
        if hits:
            lines.append(f"- **{len(hits)} open finding(s):**")
            for h in hits[:12]:
                lines.append(f"  - [{h['severity']}] `{h['check_id']}` on {h['sbc']}")
            if len(hits) > 12:
                lines.append(f"  - ... and {len(hits) - 12} more")
        else:
            lines.append("- **No open findings in this family** across the "
                         "assessed sources. (Domains a source cannot prove stay "
                         "silent and must be verified out-of-band; silence here is "
                         "the absence of detectable findings, not a certification.)")
        lines.append("")
    lines += [
        "## Evidence integrity",
        "",
        "- Validation FACTS (required roots, TLS floor, cipher allowlist) ship in an "
        f"Ed25519-signed rule bundle (version {rs_ver}) with rollback refusal.",
        "- This report is integrity-protected by the SHA-256 below (recompute over "
        "the report with the hash line blanked). It is NOT cryptographically "
        "signed; the publisher key signs rulesets only.",
        "",
        "SHA-256: {{REPORT_SHA256}}",
        "",
    ]
    body = "\n".join(lines)
    # Hash a tail-canonical form: trailing newlines carry no meaning and get
    # added/stripped by shells, `print`, and editors, so they must not affect
    # the content hash (otherwise a forwarded report fails its own check).
    canonical = body.replace("{{REPORT_SHA256}}", "").rstrip("\n")
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return body.replace("{{REPORT_SHA256}}", digest) + "\n"


def verify_markdown(text: str) -> bool:
    """Recompute the content hash of a rendered report. True = intact."""
    import re
    m = re.search(r"SHA-256: ([0-9a-f]{64})", text)
    if not m:
        return False
    digest = m.group(1)
    blanked = text.replace(digest, "").rstrip("\n")
    return hashlib.sha256(blanked.encode("utf-8")).hexdigest() == digest


def render_html(payload: dict, framework: str) -> str:
    """Minimal self-contained HTML wrap of the Markdown (no external assets)."""
    import html as _h
    md = render_markdown(payload, framework)
    return ("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
            "<title>SBC Compliance Report</title><style>body{font-family:Georgia,"
            "serif;max-width:860px;margin:40px auto;padding:0 20px;color:#15181e;"
            "line-height:1.55}pre{white-space:pre-wrap;font-family:ui-monospace,"
            "Menlo,monospace;font-size:13px}</style></head><body><pre>"
            + _h.escape(md) + "</pre></body></html>\n")
