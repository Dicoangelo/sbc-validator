"""
One-command showcase: `sbc-validator demo`.

Runs the full multi-vendor flow against the sample configs (validate a mixed
fleet, predict a call, explain a capture, roll up 2026 CA-migration readiness),
writes per-run results, and points at the live dashboard. A portable, packaged
replacement for demo.sh that works the same from a source checkout or the
container (anywhere the sample configs and a signed ruleset are present).
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

from .parsers.audiocodes import detect_and_parse
from .rules.client import RuleClient
from .report.risk import score
from .validators.syntax_semantic import SyntaxSemanticValidator
from .validators.ca_compliance import CaComplianceValidator
from .validators.nat_traversal import NatTraversalValidator
from .validators.interop import InteropValidator
from .validators.codec import CodecValidator
from .validators.routing import RoutingValidator
from .validators.access_control import AccessControlValidator

_VALIDATORS = [SyntaxSemanticValidator, InteropValidator, CaComplianceValidator,
               NatTraversalValidator, CodecValidator, RoutingValidator, AccessControlValidator]

# curated showcase: one per vendor, mixed verdicts + a security-exposure case
_FLEET = [
    ("clean_pass.ini",        "EU-West", "AudioCodes"),
    ("audiocodes_min.ini",    "EU-West", "AudioCodes"),
    ("cisco_cube_dr.txt",     "US-West", "Cisco CUBE"),
    ("ribbon_sbc.cli",        "EU-West", "Ribbon"),
    ("oracle_teams.acli",     "APAC",    "Oracle Acme"),
    ("audiocodes_exposed.ini", "US-East", "AudioCodes"),  # healthy SBC, exposed firewall (domain S)
]
_SIM_CONFIG = "audiocodes_min.ini"   # a BLOCK config: shows the call dying at TLS
_PCAP = "reject_488.pcap"            # post-mortem of a rejected call


def _validate_one(path: Path, bundle: dict):
    cfg = detect_and_parse(path.read_text(encoding="utf-8", errors="replace"))
    findings = []
    for vcls in _VALIDATORS:
        findings.extend(vcls(bundle).validate(cfg).findings)
    return cfg, findings, score(findings)


def run_demo(args) -> int:
    samples = Path(getattr(args, "samples", None) or "samples")
    ruleset = Path(getattr(args, "ruleset", None) or "rulesets/ms_direct_routing_2026-06.json")
    out = getattr(args, "out", None) or "results"

    if not samples.is_dir() or not ruleset.is_file():
        print("demo needs the sample configs and a signed ruleset.")
        print(f"  expected samples dir: {samples}/   (--samples to override)")
        print(f"  expected ruleset:     {ruleset}    (--ruleset to override)")
        print("Run from a source checkout or the container image, where both ship.")
        return 2

    bundle = RuleClient().fetch("ms_direct_routing", local_path=str(ruleset))
    print(f"SBC Validator demo  (ruleset {bundle.get('bundle_version')})")
    print("Validating a mixed multi-vendor fleet, writing results to "
          f"{out}/ ...\n")

    from .cli import _write_result   # function-level: cli is fully loaded by now
    rows = []
    write_failed = False
    for fname, site, vendor in _FLEET:
        p = samples / fname
        if not p.exists():
            print(f"  skip {fname} (not found)")
            continue
        try:
            cfg, findings, summary = _validate_one(p, bundle)
        except Exception as e:
            print(f"  skip {fname} ({type(e).__name__}: {e})")
            continue
        report = {
            "sbc": cfg.sbc_fqdn or p.stem,
            "vendor": cfg.vendor,
            "site": site,
            "ruleset_version": bundle.get("bundle_version", "unknown"),
            "validated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "summary": summary,
            "findings": [vars(f) | {"severity": f.severity.name} for f in findings],
        }
        try:
            _write_result(out, report)        # for the live dashboard; not required to show results
        except OSError:
            write_failed = True
        rows.append((report["sbc"], vendor, summary["verdict"], summary["risk_score"]))

    print(f"  {'SBC':26} {'VENDOR':12} {'VERDICT':8} RISK")
    print("  " + "-" * 52)
    for sbc, vendor, verdict, risk in sorted(rows, key=lambda r: -r[3]):
        print(f"  {sbc:26} {vendor:12} {verdict:8} {risk:>3}")

    # one prediction + one post-mortem: the vet-floor pair
    sim_p = samples / _SIM_CONFIG
    if sim_p.exists():
        from .call_sim import simulate_call
        cfg, findings, _ = _validate_one(sim_p, bundle)
        sim = simulate_call(cfg, bundle, findings)
        print(f"\n  Predicted call ({_SIM_CONFIG}): {sim.outcome}"
              + (f", dies at {sim.dies_at}" if sim.dies_at else "") + f"\n    {sim.summary}")

    pcap_p = samples / _PCAP
    if pcap_p.exists():
        from .sip_trace import analyze
        try:
            res = analyze(str(pcap_p))
            diag = None
            if res.get("top_diagnoses"):
                d = res["top_diagnoses"][0]
                diag = f"[{d['domain']}] {d['headline']}"
            elif res.get("calls"):
                c = res["calls"][0]
                ds = c.get("diagnoses") or []
                diag = f"{c.get('outcome')}" + (f" - {ds[0]['headline']}" if ds else "")
            if diag:
                print(f"\n  Explained capture ({_PCAP}): {diag}")
        except Exception:
            pass

    # security posture: surface a domain-S exposure if one is in the fleet
    sec_p = samples / "audiocodes_exposed.ini"
    if sec_p.exists():
        _, sec_findings, _ = _validate_one(sec_p, bundle)
        s = [f for f in sec_findings if f.check_id.startswith("S.")]
        if s:
            top = max(s, key=lambda f: f.severity)
            print(f"\n  Security posture (audiocodes_exposed.ini): {len(s)} access-control "
                  f"findings, top [{top.severity.name}] {top.check_id}\n    {top.title}")

    # 2026 readiness rollup over the curated set
    from .fleet import run_fleet, render_markdown
    paths = [str(samples / f) for f, *_ in _FLEET if (samples / f).exists()]
    fleet = run_fleet(paths, bundle)
    print(f"\n  2026 CA readiness: {fleet['ca_2026_ready']} of {fleet['total']} SBCs ready"
          f"  ({fleet['ca_2026_not_ready']} carry a TLS/CA/cert/SRTP blocker)")

    if write_failed:
        print(f"\nDone. (Could not write results to {out}/ - read-only path; pass "
              "--out to a writable dir to feed the live dashboard.)")
    else:
        print(f"\nDone. See the live dashboard:  sbc-validator serve --results {out}")
    return 0
