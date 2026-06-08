"""
Build the dashboard payload from a results directory.

    python -m sbc_validator.tools.build_dashboard_data results/ -o dashboard_data.json
    # privacy-preserving fleet view (tokens, counts only — no FQDNs/sites):
    python -m sbc_validator.tools.build_dashboard_data results/ -o dashboard_data.json --anon --org-salt <salt>

Reads every <sbc>/<timestamp>.json the CLI wrote, takes the LATEST run per SBC
for the fleet table, and builds a per-day open-findings-by-severity trend from
the full history. Output shape matches what sbc_dashboard.html expects:

    { "generated_at": "...", "ruleset_version": "...",
      "fleet": [ { sbc, vendor, site, ruleset_version, summary, findings, top } ],
      "trend": { "labels": [...], "series": { CRITICAL:[...], HIGH:[...], MEDIUM:[...], LOW:[...] } } }

Local-first: this runs inside the trust boundary over local result files. With
--anon it emits the redacted view (org token instead of FQDN, no site/locator),
suitable for a cross-tenant hosted panel.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
TREND_SEV = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def _load_runs(results_dir: Path) -> list[dict]:
    runs = []
    for f in results_dir.glob("*/*.json"):
        try:
            runs.append(json.loads(f.read_text()))
        except Exception as e:  # skip unreadable files, keep going
            print(f"skip {f}: {e}", file=sys.stderr)
    return runs


def _latest_per_sbc(runs: list[dict]) -> list[dict]:
    latest: dict[str, dict] = {}
    for r in runs:
        k = r.get("sbc", "?")
        if k not in latest or r.get("validated_at", "") > latest[k].get("validated_at", ""):
            latest[k] = r
    return list(latest.values())


def _top_finding(findings: list[dict]) -> str:
    if not findings:
        return "—"
    ranked = sorted(findings, key=lambda x: SEV_ORDER.index(x.get("severity", "INFO")))
    return ranked[0].get("check_id", "—")


def _anonymize(run: dict, salt: str) -> dict:
    token = hashlib.sha256(f"{salt}:{run.get('sbc','')}".encode()).hexdigest()[:12]
    return {
        "sbc": token,                       # token instead of FQDN
        "vendor": run.get("vendor", "unknown"),
        "site": "—",                        # site stripped
        "ruleset_version": run.get("ruleset_version", "unknown"),
        "summary": run.get("summary", {}),
        # findings reduced to check_id + severity + domain only (no detail/locator)
        "findings": [
            {"check_id": x.get("check_id"), "severity": x.get("severity"),
             "domain": x.get("domain") or (x.get("check_id", "?").split(".", 1)[0])}
            for x in run.get("findings", [])
        ],
        "top": _top_finding(run.get("findings", [])),
    }


def _fleet_entry(run: dict) -> dict:
    out = dict(run)
    out["top"] = _top_finding(run.get("findings", []))
    # ensure each finding carries a domain
    for x in out.get("findings", []):
        x.setdefault("domain", x.get("check_id", "?").split(".", 1)[0])
    return out


def _build_trend(runs: list[dict]) -> dict:
    by_day = defaultdict(lambda: {s: 0 for s in TREND_SEV})
    for r in runs:
        day = (r.get("validated_at", "") or "")[:10]
        if not day:
            continue
        for x in r.get("findings", []):
            s = x.get("severity")
            if s in by_day[day]:
                by_day[day][s] += 1
    days = sorted(by_day)
    labels = [datetime.fromisoformat(d).strftime("%b %-d") if d else d for d in days]
    series = {s: [by_day[d][s] for d in days] for s in TREND_SEV}
    return {"labels": labels, "series": series}


def build_payload(results_dir, anon: bool = False, org_salt: str = "unsalted") -> dict | None:
    """Build the dashboard payload dict from a results directory.

    Returns None if the directory has no result files yet. Factored out so the
    local `serve` command can rebuild the payload in-memory on every request
    (live dashboard) without writing a file.
    """
    rdir = Path(results_dir)
    if not rdir.exists():
        return None
    runs = _load_runs(rdir)
    if not runs:
        return None
    latest = _latest_per_sbc(runs)
    fleet = [_anonymize(r, org_salt) if anon else _fleet_entry(r) for r in latest]
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "ruleset_version": (latest[0].get("ruleset_version") if latest else "unknown"),
        "mode": "anon" if anon else "internal",
        "fleet": fleet,
        "trend": _build_trend(runs),
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="build_dashboard_data")
    ap.add_argument("results_dir")
    ap.add_argument("-o", "--out", default="dashboard_data.json")
    ap.add_argument("--anon", action="store_true", help="redacted cross-tenant view")
    ap.add_argument("--org-salt", default="unsalted")
    args = ap.parse_args(argv)

    if not Path(args.results_dir).exists():
        print(f"no such results dir: {args.results_dir}", file=sys.stderr)
        return 2
    payload = build_payload(args.results_dir, anon=args.anon, org_salt=args.org_salt)
    if payload is None:
        print("no result files found (run the validator with --out first)", file=sys.stderr)
        return 1
    Path(args.out).write_text(json.dumps(payload, indent=2))
    print(f"wrote {args.out}: {len(payload['fleet'])} SBCs, mode={payload['mode']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
