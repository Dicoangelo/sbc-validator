"""Freeze the demo dashboard into a static bundle for the visible (hosted) layer.

The LIVE dashboard (`sbc-validator serve`) is local-first by design: it reads a
results/ directory full of a customer's real SBC FQDNs, configs, and posture, so
it must never be hosted. This script produces the opposite artifact: a static,
read-only DEMO of the same UI, fed the anonymized sample fleet run through the
REAL validators, so a prospect can SEE the product without installing anything.

Output (default marketing/dashboard/):
    index.html            # the exact dashboard view, copied verbatim (no fork)
    dashboard_data.json   # the demo fleet payload (mode: "demo"), real verdicts
    walk-broken.json      # frozen `walk` output for the broken sample
    walk-fixed.json       # frozen `walk` output for the fixed sample
    chart.umd.min.js      # the charting asset

The same sbc_dashboard.html drives both modes: live endpoints when served by
`serve`, static sibling JSON when hosted (the /walk fetch falls back; the data
load already reads ./dashboard_data.json; /scan routes to Fly via a Vercel
rewrite). Nothing here is synthetic — every verdict is the validator's own.
"""
from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

from ..rules.client import RuleClient
from .. import serve as _serve


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent.parent


def build(out_dir: Path, ruleset: Path) -> int:
    root = _repo_root()
    web = root / "sbc_validator" / "web"
    if not ruleset.is_file():
        print(f"ruleset not found: {ruleset}")
        return 2

    # The demo helpers resolve sample/cert paths relative to cwd; run from root so
    # verdicts match `sbc-validator demo` exactly (cert PEMs are relative refs).
    import os
    os.chdir(root)
    bundle = RuleClient().fetch("ms_direct_routing", local_path=str(ruleset))

    payload = _serve._demo_payload(bundle)
    if not payload.get("fleet"):
        print("demo payload empty — sample fleet did not resolve.")
        return 2

    out_dir.mkdir(parents=True, exist_ok=True)
    # 1. the dashboard view, verbatim (single source of truth, no fork)
    shutil.copyfile(web / "sbc_dashboard.html", out_dir / "index.html")
    shutil.copyfile(web / "chart.umd.min.js", out_dir / "chart.umd.min.js")
    # 2. the frozen demo fleet (real verdicts), loaded on page open
    (out_dir / "dashboard_data.json").write_text(
        json.dumps(payload, indent=2), encoding="utf-8")
    # 3. the frozen walkthrough, broken + fixed (real engine output)
    for which in ("broken", "fixed"):
        text = _serve._walk_text(which, bundle)
        (out_dir / f"walk-{which}.json").write_text(
            json.dumps({"which": which, "output": text}), encoding="utf-8")

    verdicts = [s.get("summary", {}).get("verdict") for s in payload["fleet"]]
    rel = out_dir.relative_to(root) if out_dir.is_relative_to(root) else out_dir
    print(f"static demo dashboard -> {rel}/  ({len(payload['fleet'])} SBCs, "
          f"verdicts {verdicts}, ruleset {bundle.get('bundle_version')})")
    print("  files: index.html dashboard_data.json walk-broken.json "
          "walk-fixed.json chart.umd.min.js")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="freeze the static demo dashboard")
    ap.add_argument("--out", default="marketing/dashboard",
                    help="output dir (default: marketing/dashboard)")
    ap.add_argument("--ruleset", default="rulesets/ms_direct_routing_2026-06.json",
                    help="signed rule bundle to validate the demo fleet against")
    args = ap.parse_args(argv)
    return build(Path(args.out).resolve(), (_repo_root() / args.ruleset))


if __name__ == "__main__":
    raise SystemExit(main())
