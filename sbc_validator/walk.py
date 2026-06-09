"""Guided end-to-end walkthrough of one SBC config.

`sbc-validator walk <config>` narrates the whole pipeline in stages, so a reviewer
sees exactly how a config becomes a verdict: ingest -> normalized model -> each
validation domain firing -> verdict -> predicted call. It runs the same engine as
`validate`; it just shows its work.
"""
from __future__ import annotations

from .report.risk import score
from .validators.syntax_semantic import SyntaxSemanticValidator
from .validators.interop import InteropValidator
from .validators.ca_compliance import CaComplianceValidator
from .validators.nat_traversal import NatTraversalValidator
from .validators.codec import CodecValidator
from .validators.routing import RoutingValidator
from .validators.access_control import AccessControlValidator

# (validator, domain letter, what it checks) — the order a call actually depends on.
_DOMAINS = [
    (SyntaxSemanticValidator, "A", "syntax & semantic baseline (well-formed, no dangling refs)"),
    (InteropValidator,        "B", "interop: TLS transport, OPTIONS keep-alive, header normalization"),
    (CaComplianceValidator,   "C", "the 2026 wedge: mTLS, the 7 required roots, SRTP, cert + chain"),
    (NatTraversalValidator,   "D", "NAT / media: advertised address, symmetric RTP (one-way audio)"),
    (CodecValidator,          "E", "codec: cross-leg overlap, transcode, DTMF"),
    (RoutingValidator,        "G", "routing & classification (fires only if the source carries it)"),
    (AccessControlValidator,  "S", "security: ACL default-deny, broad CIDR, IPv6, shadowing"),
]

_RULE = "─" * 72
_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _yn(v):
    return "unknown" if v is None else ("yes" if v else "no")


def _stage(n, title):
    print(f"\n{_RULE}\n  STAGE {n} — {title}\n{_RULE}")


def walk_report(config, bundle: dict) -> int:
    ver = bundle.get("bundle_version", "?")
    print(f"\n  SBC Validator — guided walkthrough")
    print(f"  config vendor: {config.vendor}    ruleset: {ver}")

    # ── STAGE 1: ingest -> normalized model ──────────────────────────────────
    _stage(1, "INGEST  (raw vendor config → one normalized model)")
    print(f"  SBC FQDN: {config.sbc_fqdn or '(none)'}")
    teams = config.teams_interface()
    carrier = config.carrier_interface()
    if teams:
        ctx = teams.tls_context
        roots = len(ctx.trusted_root_ids) if ctx else 0
        print("  Teams leg:")
        print(f"      transport={teams.transport or 'unknown'}   mTLS={_yn(ctx.mtls_enabled if ctx else None)}"
              f"   SRTP={_yn(teams.srtp_enabled)}   keep-alive={_yn(teams.options_keepalive)}")
        print(f"      codecs={teams.offered_codecs or '[]'}   trusted roots in store: {roots}")
    else:
        print("  Teams leg: NONE identified (role='teams') — downstream C/B can't apply")
    if carrier:
        print(f"  Carrier leg: transport={carrier.transport or 'unknown'}   "
              f"keep-alive={_yn(carrier.options_keepalive)}   codecs={carrier.offered_codecs or '[]'}")
    for m in config.media_realms:
        print(f"  Media realm '{m.name}': advertised={m.advertised_public_ip or '(none)'}   "
              f"symmetric-RTP={_yn(m.symmetric_rtp)}")
    print("\n  → Every check below reads THIS model, never the raw vendor syntax.")

    # ── STAGE 2: validate, domain by domain ──────────────────────────────────
    _stage(2, "VALIDATE  (each domain reasons over the model)")
    all_findings = []
    for vcls, letter, desc in _DOMAINS:
        res = vcls(bundle).validate(config)
        fs = sorted(res.findings, key=lambda f: _SEV_ORDER.get(f.severity.name, 9))
        all_findings.extend(res.findings)
        head = f"  [{letter}] {desc}"
        if not fs:
            print(f"{head}\n        ✓ clean (or silent: nothing in the source to judge)")
            continue
        print(head)
        for f in fs:
            print(f"        [{f.severity.name:8}] {f.check_id}  —  {f.title}")
            print(f"                  why: {f.detail}")
            print(f"                  fix: {f.remediation}")

    # ── STAGE 3: verdict ─────────────────────────────────────────────────────
    _stage(3, "VERDICT  (severity-weighted; any CRITICAL forces BLOCK)")
    summary = score(all_findings)
    counts = summary["counts"]
    print(f"  Risk score: {summary['risk_score']}/100      VERDICT: {summary['verdict']}")
    breakdown = ", ".join(f"{k} {counts[k]}" for k in
                          ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO") if counts.get(k))
    print(f"  Findings: {breakdown or 'none'}")

    # ── STAGE 4: predicted call ──────────────────────────────────────────────
    _stage(4, "PREDICT  (model the call: TLS → SIP → SDP → media)")
    from .call_sim import simulate_call
    sim = simulate_call(config, bundle, all_findings)
    print(f"  Outcome: {sim.outcome}" + (f"   (dies at: {sim.dies_at})" if sim.dies_at else ""))
    print(f"  {sim.summary}\n")
    for line in sim.ladder:
        print("  " + line)

    # ── STAGE 5: next step ───────────────────────────────────────────────────
    _stage(5, "NEXT")
    if summary["verdict"] == "PASS":
        print("  PASS — ready for the 2026 CA migration. Re-run after any config change.")
    else:
        print("  Apply the fixes above to the SBC config, then re-run:")
        print("      sbc-validator validate <config> --ruleset <ruleset>")
        print("  to confirm it turns green. (See samples/walkthrough/ for a broken→fixed pair.)")
    print()
    return 0
