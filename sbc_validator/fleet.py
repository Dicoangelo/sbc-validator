"""
Fleet readiness: validate a directory of SBC configs and roll the per-SBC results
up into one executive answer to the question a buyer actually asks - "are my 50+
SBCs ready for the 2026 Microsoft CA migration?"

Reuses the same parse -> A-G validators -> score pipeline per config, then
aggregates: verdict counts, 2026-CA readiness (how many carry a TLS/CA/cert/SRTP
blocker), and the most common findings across the fleet. Renders a portable
Markdown report. Local-first like everything else: it only reads local files.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone

from .parsers.audiocodes import detect_and_parse
from .report.risk import score
from .validators.syntax_semantic import SyntaxSemanticValidator
from .validators.interop import InteropValidator
from .validators.ca_compliance import CaComplianceValidator
from .validators.nat_traversal import NatTraversalValidator
from .validators.codec import CodecValidator
from .validators.routing import RoutingValidator
from .validators.access_control import AccessControlValidator

_VALIDATORS = [SyntaxSemanticValidator, InteropValidator, CaComplianceValidator,
               NatTraversalValidator, CodecValidator, RoutingValidator, AccessControlValidator]

# A "2026 CA migration blocker": a TLS/CA/cert/SRTP problem at HIGH or worse.
_CA_PREFIXES = ("C.CA.", "C.CERT.", "C.TLS.", "C.SRTP")


def _top_finding(findings):
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    ranked = sorted(findings, key=lambda f: order.get(f.severity.name, 9))
    return ranked[0].check_id if ranked else "-"


def validate_one(path: str, bundle: dict) -> dict | None:
    try:
        text = open(path, encoding="utf-8", errors="replace").read()
        cfg = detect_and_parse(text)
    except Exception:
        return None
    findings = []
    for v in _VALIDATORS:
        findings.extend(v(bundle).validate(cfg).findings)
    summary = score(findings)
    blocker = any(
        f.check_id.startswith(_CA_PREFIXES) and f.severity.name in ("CRITICAL", "HIGH")
        for f in findings)
    teams = cfg.teams_interface()
    cert_cn = None
    if teams is not None and teams.tls_context is not None \
            and teams.tls_context.presented_cert is not None:
        cert_cn = teams.tls_context.presented_cert.subject_cn
    return {
        "sbc": cfg.sbc_fqdn or path.rsplit("/", 1)[-1],
        "vendor": cfg.vendor,
        "verdict": summary["verdict"],
        "risk": summary["risk_score"],
        "top": _top_finding(findings),
        "ca_2026_ready": not blocker,
        "check_ids": [f.check_id for f in findings],
        # Multi-tenant signals: the cert identity this tenant's Teams leg presents
        # (tenants sharing one carrier wildcard cert share its fate).
        "cert_cn": cert_cn,
    }


def run_fleet(paths: list[str], bundle: dict, multi_tenant: bool = False) -> dict:
    rows = [r for r in (validate_one(p, bundle) for p in sorted(paths)) if r]
    verdicts = Counter(r["verdict"] for r in rows)
    ready = sum(1 for r in rows if r["ca_2026_ready"])
    common = Counter(cid for r in rows for cid in r["check_ids"])
    out = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "ruleset_version": bundle.get("bundle_version", "unknown"),
        "total": len(rows),
        "verdicts": dict(verdicts),
        "ca_2026_ready": ready,
        "ca_2026_not_ready": len(rows) - ready,
        "top_findings": common.most_common(8),
        "fleet": rows,
    }
    if multi_tenant:
        out["tenants"] = _tenant_analysis(rows)
    return out


def _tenant_analysis(rows: list[dict]) -> dict:
    """Carrier/SBCaaS view: each config is one tenant. The cascade question is the
    one a fleet operator actually fears: tenants sharing one carrier cert (the
    wildcard *.base-domain pattern from Microsoft's multi-tenant model) share its
    fate, so a single cert blocker takes them ALL down simultaneously."""
    by_cert: dict[str, list[dict]] = {}
    for r in rows:
        if r.get("cert_cn"):
            by_cert.setdefault(r["cert_cn"], []).append(r)
    cascades = []
    for cn, members in sorted(by_cert.items()):
        if len(members) < 2:
            continue                      # a cert unique to one tenant cannot cascade
        blocked = [m["sbc"] for m in members if not m["ca_2026_ready"]]
        cascades.append({
            "cert_cn": cn,
            "tenants": [m["sbc"] for m in members],
            "shared_by": len(members),
            "blocked_members": blocked,
            # One bad shared cert = every tenant on it fails at the same moment.
            "cascade_risk": bool(blocked),
        })
    contact_mismatches = [r["sbc"] for r in rows
                          if "B.SIP.CONTACT_FQDN" in r["check_ids"]]
    return {
        "total": len(rows),
        "ready": sum(1 for r in rows if r["ca_2026_ready"]),
        "shared_certs": cascades,
        "at_cascade_risk": sorted({t for c in cascades if c["cascade_risk"]
                                   for t in c["tenants"]}),
        "contact_fqdn_mismatches": contact_mismatches,
    }


def render_markdown(result: dict) -> str:
    t = result["total"]
    v = result["verdicts"]
    not_ready = result["ca_2026_not_ready"]
    lines = [
        "# SBC Fleet Readiness Report",
        "",
        f"_Ruleset {result['ruleset_version']} - generated {result['generated_at']}_",
        "",
        "## 2026 Microsoft CA migration readiness",
        "",
        f"**{result['ca_2026_ready']} of {t} SBCs ready.** "
        + (f"**{not_ready} not ready** (carry a TLS/CA/cert/SRTP blocker)."
           if not_ready else "No CA/cert blockers across the fleet."),
        "",
        "## Deploy verdicts",
        "",
        f"- PASS: {v.get('PASS', 0)}",
        f"- REVIEW: {v.get('REVIEW', 0)}",
        f"- BLOCK: {v.get('BLOCK', 0)}",
        "",
        "## Fleet",
        "",
        "| SBC | Vendor | Verdict | Risk | 2026-ready | Top finding |",
        "|---|---|---|---:|:---:|---|",
    ]
    for r in sorted(result["fleet"], key=lambda x: -x["risk"]):
        ready = "yes" if r["ca_2026_ready"] else "**NO**"
        lines.append(f"| {r['sbc']} | {r['vendor']} | {r['verdict']} | {r['risk']} "
                     f"| {ready} | `{r['top']}` |")
    if result.get("tenants"):
        t = result["tenants"]
        lines += ["", "## Multi-tenant view (carrier / SBCaaS)", "",
                  f"**{t['ready']} of {t['total']} tenants ready.**"]
        risk = t["at_cascade_risk"]
        if risk:
            lines.append(f"**CASCADE RISK: {len(risk)} tenants share a blocked "
                         f"cert** and fail simultaneously: " + ", ".join(risk) + ".")
        for c in t["shared_certs"]:
            flag = " ⚠ CASCADE" if c["cascade_risk"] else ""
            lines.append(f"- Cert `{c['cert_cn']}` shared by {c['shared_by']} "
                         f"tenants{flag}"
                         + (f" (blocked: {', '.join(c['blocked_members'])})"
                            if c["blocked_members"] else ""))
        if t["contact_fqdn_mismatches"]:
            lines.append(f"- Contact-FQDN tenant-resolution mismatches: "
                         + ", ".join(t["contact_fqdn_mismatches"]))
    if result["top_findings"]:
        lines += ["", "## Most common findings", ""]
        for cid, n in result["top_findings"]:
            lines.append(f"- `{cid}` x{n}")
    lines += ["", "_SBC Validator - the independent truth layer for real-time voice._"]
    return "\n".join(lines) + "\n"
