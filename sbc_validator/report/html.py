"""
Self-contained HTML report for a single validated SBC.

Turns the report dict the CLI already produces into a styled, standalone page a
customer can read or forward. No external assets, no JS, no network — inline CSS
only, so it opens anywhere and stays inside the trust boundary like everything
else. Locators and detail are included (this is the INTERNAL artifact); the
anonymized path never goes through here.
"""
from __future__ import annotations

import html as _html

_SEV_COLOR = {
    "CRITICAL": "#b00020",
    "HIGH": "#d35400",
    "MEDIUM": "#b8860b",
    "LOW": "#3a6ea5",
    "INFO": "#6c757d",
}
_VERDICT_COLOR = {"PASS": "#1e7e34", "REVIEW": "#b8860b", "BLOCK": "#b00020"}
_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _esc(x) -> str:
    return _html.escape(str(x if x is not None else ""))


def render_html(report: dict) -> str:
    summary = report.get("summary", {})
    verdict = summary.get("verdict", "?")
    risk = summary.get("risk_score", 0)
    counts = summary.get("counts", {})
    vcolor = _VERDICT_COLOR.get(verdict, "#333")
    findings = sorted(
        report.get("findings", []),
        key=lambda f: _SEV_ORDER.get(f.get("severity", "INFO"), 9),
    )

    chips = "".join(
        f'<span class="chip" style="background:{_SEV_COLOR.get(s,"#666")}">'
        f'{_esc(s)}: {_esc(counts.get(s,0))}</span>'
        for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    )

    pred = report.get("call_prediction") or {}
    pred_html = ""
    if pred:
        good = pred.get("outcome") in ("STABLE", "DEGRADED")
        pcolor = "#1e7e34" if pred.get("outcome") == "STABLE" else (
            "#b8860b" if pred.get("outcome") == "DEGRADED" else "#b00020")
        dies = pred.get("dies_at")
        pred_html = (
            f'<div class="pred" style="border-left:4px solid {pcolor}">'
            f'<b>Predicted call outcome:</b> <span style="color:{pcolor};font-weight:700">'
            f'{_esc(pred.get("outcome"))}</span>'
            + (f' &middot; breaks at <b>{_esc(dies)}</b>' if dies else '')
            + f'<div class="predsum">{_esc(pred.get("summary"))}</div></div>'
        )

    rows = ""
    for f in findings:
        sev = f.get("severity", "INFO")
        color = _SEV_COLOR.get(sev, "#666")
        loc = f.get("locator") or ""
        rows += f"""
        <div class="finding">
          <div class="fh">
            <span class="sev" style="background:{color}">{_esc(sev)}</span>
            <code class="cid">{_esc(f.get('check_id'))}</code>
            <span class="dom">domain {_esc(f.get('domain'))}</span>
          </div>
          <div class="ft">{_esc(f.get('title'))}</div>
          {f'<div class="loc">where: {_esc(loc)}</div>' if loc else ''}
          <div class="why"><b>Why:</b> {_esc(f.get('detail'))}</div>
          <div class="fix"><b>Fix:</b> {_esc(f.get('remediation'))}</div>
        </div>"""
    if not findings:
        rows = '<div class="finding"><div class="ft">No findings. Configuration passed all checks.</div></div>'

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SBC Validator Report: {_esc(report.get('sbc'))}</title>
<style>
  :root {{ font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif; }}
  body {{ margin:0; background:#f5f6f8; color:#1a1a1a; }}
  .wrap {{ max-width: 820px; margin: 0 auto; padding: 32px 24px 64px; }}
  .top {{ display:flex; justify-content:space-between; align-items:flex-start; gap:16px; flex-wrap:wrap; }}
  h1 {{ font-size: 20px; margin:0 0 4px; }}
  .sub {{ color:#666; font-size: 13px; }}
  .verdict {{ color:#fff; background:{vcolor}; padding:10px 18px; border-radius:10px;
             font-weight:700; font-size:18px; letter-spacing:.5px; text-align:center; }}
  .verdict small {{ display:block; font-weight:500; font-size:11px; opacity:.9; }}
  .meta {{ margin:18px 0; padding:14px 16px; background:#fff; border:1px solid #e6e8eb;
           border-radius:10px; font-size:13px; display:grid; grid-template-columns:repeat(2,1fr); gap:6px 24px; }}
  .meta b {{ color:#444; }}
  .chips {{ margin:14px 0 8px; }}
  .chip {{ color:#fff; font-size:12px; padding:3px 9px; border-radius:20px; margin-right:6px; display:inline-block; }}
  .finding {{ background:#fff; border:1px solid #e6e8eb; border-radius:10px; padding:14px 16px; margin:10px 0; }}
  .fh {{ display:flex; align-items:center; gap:10px; margin-bottom:6px; flex-wrap:wrap; }}
  .sev {{ color:#fff; font-size:11px; font-weight:700; padding:2px 8px; border-radius:5px; }}
  .cid {{ font-size:12px; background:#f0f1f3; padding:2px 6px; border-radius:5px; }}
  .dom {{ font-size:11px; color:#888; }}
  .ft {{ font-weight:600; margin:2px 0; }}
  .loc {{ font-size:12px; color:#666; margin:2px 0; }}
  .why, .fix {{ font-size:13px; margin:4px 0; line-height:1.45; }}
  .fix {{ color:#1e4620; }}
  .foot {{ margin-top:28px; font-size:11px; color:#999; text-align:center; }}
  .pred {{ margin:14px 0; padding:12px 16px; background:#fff; border:1px solid #e6e8eb;
           border-radius:10px; font-size:14px; }}
  .predsum {{ font-size:13px; color:#444; margin-top:4px; }}
</style></head>
<body><div class="wrap">
  <div class="top">
    <div>
      <h1>SBC Validator Report</h1>
      <div class="sub">{_esc(report.get('sbc'))} &middot; vendor {_esc(report.get('vendor'))} &middot; site {_esc(report.get('site'))}</div>
    </div>
    <div class="verdict">{_esc(verdict)}<small>risk {_esc(risk)}/100</small></div>
  </div>
  <div class="meta">
    <div><b>Ruleset:</b> {_esc(report.get('ruleset_version'))}</div>
    <div><b>Validated:</b> {_esc(report.get('validated_at'))}</div>
    <div><b>Findings:</b> {len(findings)}</div>
    <div><b>Engine:</b> local-first (raw config never left this environment)</div>
  </div>
  <div class="chips">{chips}</div>
  {pred_html}
  {rows}
  <div class="foot">SBC Validator &middot; Metaventions AI &middot; the independent truth layer for real-time voice</div>
</div></body></html>"""
