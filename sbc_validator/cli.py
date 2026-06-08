"""
Local CLI entrypoint.

    python -m sbc_validator.cli validate <config_file> \
        --ruleset rulesets/ms_direct_routing_2026-06.json \
        [--json] [--share-anon --org-salt <salt> --consent]

Everything runs locally. The only data that can ever leave is the anonymized
payload, and only when --share-anon AND --consent are both supplied.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone

from .parsers.audiocodes import detect_and_parse
from .rules.client import RuleClient
from .validators.syntax_semantic import SyntaxSemanticValidator
from .validators.ca_compliance import CaComplianceValidator
from .validators.nat_traversal import NatTraversalValidator
from .validators.interop import InteropValidator
from .validators.codec import CodecValidator
from .validators.routing import RoutingValidator
from .validators.access_control import AccessControlValidator
from .report.risk import score
from .report.anonymize import anonymized_payload

VALIDATORS = [SyntaxSemanticValidator, InteropValidator, CaComplianceValidator,
              NatTraversalValidator, CodecValidator, RoutingValidator, AccessControlValidator]


def _read(path: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except FileNotFoundError:
        print(f"error: config file not found: {path}", file=sys.stderr)
        raise SystemExit(2)


def _parse(path: str):
    """Read + parse a config, converting ANY parser failure into a clean exit.

    A real customer export can be malformed in ways no parser fully anticipates
    (truncated tables, odd encodings, vendor quirks). The product's credibility
    rests on never spilling a Python traceback — degrade to a one-line diagnosis
    and exit 2 instead.
    """
    text = _read(path)               # already exits 2 on missing file
    try:
        return detect_and_parse(text)
    except (ValueError, NotImplementedError) as e:
        print(f"parse error: {e}", file=sys.stderr)
        raise SystemExit(2)
    except Exception as e:           # defensive: unknown parser fault, no traceback
        print(f"parse error: could not parse {path} ({type(e).__name__}: {e})",
              file=sys.stderr)
        raise SystemExit(2)


def _resolve_ruleset(path):
    """Use the given ruleset, or auto-discover the shipped bundle.

    The container and the source tree both carry the signed bundle at
    rulesets/ms_direct_routing_*.json, so `--ruleset` is optional there and
    commands stay short. A pip-only install with no bundle must pass --ruleset.
    """
    if path:
        return path
    from pathlib import Path as _P
    found = sorted(_P("rulesets").glob("ms_direct_routing_*.json"))
    return str(found[-1]) if found else None


def _load_ruleset(path: str) -> dict:
    """Fetch + verify a signed ruleset, converting any failure into a clean exit.

    A customer can be handed a corrupted, tampered, stale, or missing bundle.
    The signature/rollback refusal is a SECURITY outcome and must read as a
    one-line message, never a Python traceback.
    """
    from .rules.client import RuleVerificationError
    try:
        return RuleClient().fetch("ms_direct_routing", local_path=path)
    except RuleVerificationError as e:
        print(f"ruleset refused: {e}", file=sys.stderr)
        raise SystemExit(2)
    except FileNotFoundError:
        print(f"error: ruleset not found: {path}", file=sys.stderr)
        raise SystemExit(2)
    except (ValueError, OSError) as e:
        print(f"ruleset error: could not read {path} ({type(e).__name__}: {e})",
              file=sys.stderr)
        raise SystemExit(2)


def run(args) -> int:
    config = _parse(args.config)

    rs = _resolve_ruleset(args.ruleset)
    if rs is None:
        print("error: no ruleset found; pass --ruleset <signed bundle>", file=sys.stderr)
        return 2
    bundle = _load_ruleset(rs)
    ruleset_version = bundle.get("bundle_version", "unknown")

    findings = []
    for vcls in VALIDATORS:
        findings.extend(vcls(bundle).validate(config).findings)

    summary = score(findings)

    # Full report record — this is the per-SBC shape the dashboard consumes.
    report = {
        "sbc": config.sbc_fqdn or os.path.splitext(os.path.basename(args.config))[0],
        "vendor": config.vendor,
        "site": args.site or config.raw_meta.get("site") or "unspecified",
        "ruleset_version": ruleset_version,   # freshness assertion stamped in
        "validated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "summary": summary,
        "findings": [vars(f) | {"severity": f.severity.name} for f in findings],
    }

    # Predicted call outcome (deterministic, offline) — included on every report.
    from .call_sim import simulate_call
    sim = simulate_call(config, bundle, findings)
    report["call_prediction"] = {
        "outcome": sim.outcome, "dies_at": sim.dies_at, "summary": sim.summary,
    }

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        _print_human(report["vendor"], ruleset_version, summary, findings)
        print(f"\nPredicted call: {sim.outcome}"
              + (f" (dies at {sim.dies_at})" if sim.dies_at else "") + f" — {sim.summary}")

    if args.out:
        path = _write_result(args.out, report)
        if not args.json:
            print(f"\n[out] wrote {path}")

    if args.html:
        from .report.html import render_html
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(render_html(report))
        if not args.json:
            print(f"[html] wrote {args.html}")

    if args.share_anon:
        if not args.consent:
            print("\n[anon] refused: --share-anon requires explicit --consent", file=sys.stderr)
        else:
            payload = anonymized_payload(findings, config.vendor, ruleset_version,
                                         args.org_salt or "unsalted")
            print("\n[anon] payload eligible for export (NOT sent by skeleton):")
            print(json.dumps(payload, indent=2))

    # CI gate: exit non-zero on the chosen verdict-or-worse (default: BLOCK only).
    levels = {"PASS": 0, "REVIEW": 1, "BLOCK": 2}
    threshold = {"block": 2, "review": 1}[getattr(args, "fail_on", "block")]
    return 1 if levels.get(summary["verdict"], 0) >= threshold else 0


def _write_result(out_dir: str, report: dict) -> str:
    """Write one run as results/<sbc>/<timestamp>.json (history-preserving)."""
    safe_sbc = report["sbc"].replace("/", "_").replace(" ", "_")
    ts = report["validated_at"].replace(":", "").replace("-", "").replace("+0000", "Z")
    d = os.path.join(out_dir, safe_sbc)
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, f"{ts}.json")
    with open(path, "w") as fh:
        json.dump(report, fh, indent=2)
    return path


def _print_human(vendor, version, summary, findings):
    print(f"SBC Validator — vendor={vendor}  ruleset={version}")
    print(f"Verdict: {summary['verdict']}   Risk score: {summary['risk_score']}/100")
    print("-" * 60)
    order = sorted(findings, key=lambda f: f.severity, reverse=True)
    for f in order:
        print(f"[{f.severity.name:8}] {f.check_id}  {f.title}")
        if f.locator:
            print(f"           where: {f.locator}")
        print(f"           why  : {f.detail}")
        print(f"           fix  : {f.remediation}")
    if not findings:
        print("No findings. (Verify the parser actually populated the model.)")


def run_simulate(args) -> int:
    """Predict how far a real call would get, from static config alone."""
    from .call_sim import simulate_call
    config = _parse(args.config)
    rs = _resolve_ruleset(args.ruleset)
    if rs is None:
        print("error: no ruleset found; pass --ruleset <signed bundle>", file=sys.stderr)
        return 2
    bundle = _load_ruleset(rs)
    findings = []
    for vcls in VALIDATORS:
        findings.extend(vcls(bundle).validate(config).findings)
    sim = simulate_call(config, bundle, findings)

    if args.json:
        print(json.dumps({
            "sbc": config.sbc_fqdn, "vendor": config.vendor,
            "outcome": sim.outcome, "dies_at": sim.dies_at, "summary": sim.summary,
            "negotiated_codec": sim.negotiated_codec, "transcode_required": sim.transcode_required,
            "stages": [vars(s) for s in sim.stages], "ladder": sim.ladder,
        }, indent=2))
        return 0

    print(f"Call simulation — {config.sbc_fqdn or args.config}  (vendor={config.vendor})")
    print(f"Predicted outcome: {sim.outcome}" +
          (f"   (dies at: {sim.dies_at})" if sim.dies_at else ""))
    print(sim.summary)
    print("-" * 64)
    glyph = {"ok": "[ok]  ", "warn": "[warn]", "fail": "[FAIL]"}
    for s in sim.stages:
        print(f"{glyph.get(s.status,'')} {s.name}: {s.detail}")
        if s.symptom:
            print(f"        symptom: {s.symptom}")
    print("\nPredicted SIP ladder:")
    for line in sim.ladder:
        print("  " + line)
    return 0


def run_explain(args) -> int:
    """Post-mortem: reconstruct the SIP ladder from a pcap and explain failures."""
    from .sip_trace import analyze
    try:
        result = analyze(args.capture)
    except FileNotFoundError:
        print(f"error: capture file not found: {args.capture}", file=sys.stderr)
        return 2
    except Exception as e:           # malformed pcap must not spill a traceback
        print(f"error: could not read capture {args.capture} "
              f"({type(e).__name__}: {e})", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(result, indent=2))
        return 0
    print(f"Capture: {result['file']}")
    print(f"{result['packets']} packets, {result['sip_messages']} SIP messages, "
          f"{len(result['rtp_flows'])} RTP flow(s)")
    for d in result["top_diagnoses"]:
        print(f"\n[{d['domain']}] {d['headline']}\n    {d['detail']}\n    fix: {d['fix']}")
    for c in result["calls"]:
        print("\n" + "=" * 64)
        print(f"Call-ID {c['call_id']}   outcome: {c['outcome']}")
        print("SIP ladder:")
        for line in c["ladder"]:
            print("  " + line)
        for d in c["diagnoses"]:
            print(f"\n  [{d['domain']}] {d['headline']}")
            print(f"      why: {d['detail']}")
            print(f"      fix: {d['fix']}")
    if not result["calls"] and not result["top_diagnoses"]:
        print("\nNo SIP calls found in the capture.")
    return 0


def run_fleet(args) -> int:
    """Validate a directory of configs and roll up a fleet readiness report."""
    import glob
    from .fleet import run_fleet as _run_fleet, render_markdown
    rs = _resolve_ruleset(args.ruleset)
    if rs is None:
        print("error: no ruleset found; pass --ruleset <signed bundle>", file=sys.stderr)
        return 2
    bundle = _load_ruleset(rs)
    paths = sorted(p for p in glob.glob(os.path.join(args.directory, "*"))
                   if os.path.isfile(p))
    result = _run_fleet(paths, bundle)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        md = render_markdown(result)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(md)
            print(f"[fleet] wrote {args.out}  ({result['total']} SBCs, "
                  f"{result['ca_2026_not_ready']} not 2026-ready)")
        else:
            print(md)
    # gate: non-zero if any SBC isn't ready for the 2026 migration
    return 1 if result["ca_2026_not_ready"] else 0


def run_diff(args) -> int:
    """HA drift: compare an Active node config against its Standby."""
    from .validators.ha_drift import ha_diff
    active = _parse(args.active)
    standby = _parse(args.standby)
    findings = ha_diff(active, standby)
    summary = score(findings)

    if args.json:
        print(json.dumps({
            "active": active.sbc_fqdn, "standby": standby.sbc_fqdn,
            "summary": summary,
            "findings": [vars(f) | {"severity": f.severity.name} for f in findings],
        }, indent=2))
    else:
        print(f"HA Drift — active={active.sbc_fqdn}  standby={standby.sbc_fqdn}")
        print(f"Verdict: {summary['verdict']}   Drift score: {summary['risk_score']}/100")
        print("-" * 60)
        for f in sorted(findings, key=lambda f: f.severity, reverse=True):
            print(f"[{f.severity.name:8}] {f.check_id}  {f.title}")
            print(f"           why  : {f.detail}")
            print(f"           fix  : {f.remediation}")
        if not findings:
            print("No drift. Standby matches active on all failover-critical fields.")
    return 1 if summary["verdict"] == "BLOCK" else 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="sbc-validator")
    sub = p.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("validate", help="validate a local SBC config export")
    v.add_argument("config")
    v.add_argument("--ruleset", default=None, help="signed rule bundle (default: the shipped one)")
    v.add_argument("--json", action="store_true")
    v.add_argument("--out", default=None,
                   help="write this run to <out>/<sbc>/<timestamp>.json for the dashboard")
    v.add_argument("--site", default=None, help="deployment site/region label for the dashboard")
    v.add_argument("--html", default=None,
                   help="write a self-contained customer-facing HTML report to this path")
    v.add_argument("--share-anon", action="store_true",
                   help="build anonymized telemetry payload (off by default)")
    v.add_argument("--consent", action="store_true", help="explicit consent gate")
    v.add_argument("--org-salt", default=None)
    v.add_argument("--fail-on", choices=["block", "review"], default="block",
                   help="CI gate: exit non-zero on this verdict or worse (default: block)")
    v.set_defaults(func=run)

    d = sub.add_parser("diff", help="detect HA config drift between two node configs")
    d.add_argument("active", help="active node config export")
    d.add_argument("standby", help="standby node config export")
    d.add_argument("--json", action="store_true")
    d.set_defaults(func=run_diff)

    sm = sub.add_parser("simulate",
                        help="predict the call flow (TLS->SIP->SDP->media) from config")
    sm.add_argument("config")
    sm.add_argument("--ruleset", default=None, help="signed rule bundle (default: the shipped one)")
    sm.add_argument("--json", action="store_true")
    sm.set_defaults(func=run_simulate)

    ex = sub.add_parser("explain",
                        help="post-mortem: reconstruct the SIP ladder from a .pcap and diagnose")
    ex.add_argument("capture", help="path to a classic .pcap capture")
    ex.add_argument("--json", action="store_true")
    ex.set_defaults(func=run_explain)

    fl = sub.add_parser("fleet",
                        help="validate a directory of configs -> fleet readiness report")
    fl.add_argument("directory", help="directory of SBC config exports")
    fl.add_argument("--ruleset", default=None, help="signed rule bundle (default: the shipped one)")
    fl.add_argument("--out", default=None, help="write the Markdown report to this path")
    fl.add_argument("--json", action="store_true")
    fl.set_defaults(func=run_fleet)

    sv = sub.add_parser("serve",
                        help="serve the local dashboard over a live results directory")
    sv.add_argument("--results", default="results",
                    help="directory of per-run JSON (validate --out wrote these)")
    sv.add_argument("--host", default="127.0.0.1",
                    help="bind address (default loopback; widen only deliberately)")
    sv.add_argument("--port", type=int, default=8787)
    sv.add_argument("--anon", action="store_true",
                    help="serve the redacted cross-tenant view (tokens, no FQDN/site)")
    sv.add_argument("--org-salt", default="unsalted")
    sv.set_defaults(func=lambda a: __import__("sbc_validator.serve", fromlist=["run_serve"]).run_serve(a))

    dm = sub.add_parser("demo",
                        help="one-command multi-vendor showcase (validate + predict + explain + readiness)")
    dm.add_argument("--samples", default=None, help="sample config dir (default: samples)")
    dm.add_argument("--ruleset", default=None, help="signed rule bundle (default: the shipped one)")
    dm.add_argument("--out", default="results", help="where to write per-run results (default: results)")
    dm.set_defaults(func=lambda a: __import__("sbc_validator.demo", fromlist=["run_demo"]).run_demo(a))

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
