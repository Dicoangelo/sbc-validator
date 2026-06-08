"""
Fleet executive report.

A single, self-contained, forwardable artifact (the leave-behind after a demo):
fleet verdicts, 2026 Microsoft CA-migration readiness, security posture, and the
most common findings, rendered from a results directory. No server, no JS, inline
CSS only, injection-safe (every dynamic value through html.escape).
"""
from __future__ import annotations

import html as _html
from collections import Counter

_VERDICT_COLOR = {"PASS": "#1e7e34", "REVIEW": "#b8860b", "BLOCK": "#b00020"}
# A finding that blocks 2026 CA-migration readiness.
_CA_PREFIXES = ("C.CA", "C.CERT", "C.TLS", "C.SRTP")
_HIGH = {"HIGH", "CRITICAL"}


def _esc(x) -> str:
    return _html.escape(str(x if x is not None else ""))


def _not_ready(sbc: dict) -> bool:
    return any(f.get("check_id", "").startswith(_CA_PREFIXES)
               and f.get("severity") in _HIGH
               for f in sbc.get("findings", []))


def summarize(payload: dict) -> dict:
    fleet = payload.get("fleet", [])
    verdicts = Counter(s.get("summary", {}).get("verdict", "?") for s in fleet)
    not_ready = [s for s in fleet if _not_ready(s)]
    with_sec = [s for s in fleet if any(f.get("check_id", "").startswith("S.")
                                        for f in s.get("findings", []))]
    common = Counter(f.get("check_id") for s in fleet for f in s.get("findings", [])
                     if f.get("severity") in _HIGH)
    return {
        "total": len(fleet),
        "verdicts": verdicts,
        "ca_ready": len(fleet) - len(not_ready),
        "ca_not_ready": len(not_ready),
        "security_exposed": len(with_sec),
        "top_findings": common.most_common(8),
        "ruleset_version": payload.get("ruleset_version", "unknown"),
        "generated_at": payload.get("generated_at", ""),
    }


def render_markdown(payload: dict) -> str:
    s = summarize(payload)
    L = [f"# SBC Fleet Executive Report",
         "",
         f"_Ruleset {s['ruleset_version']} - {s['total']} SBCs - generated {s['generated_at']}_",
         "",
         "## 2026 Microsoft CA migration readiness",
         "",
         f"**{s['ca_ready']} of {s['total']} SBCs ready.** {s['ca_not_ready']} carry a "
         "TLS/CA/cert/SRTP blocker.",
         "",
         "## Deploy verdicts",
         ""]
    for v in ("BLOCK", "REVIEW", "PASS"):
        if s["verdicts"].get(v):
            L.append(f"- {v}: {s['verdicts'][v]}")
    L += ["", "## Security posture", "",
          f"**{s['security_exposed']} of {s['total']} SBCs** have an access-control "
          "(domain S) exposure.", "", "## Most common high-severity findings", ""]
    for cid, n in s["top_findings"]:
        L.append(f"- `{cid}` x{n}")
    L += ["", "_SBC Validator - the independent truth layer for real-time voice._"]
    return "\n".join(L)


def render_html(payload: dict) -> str:
    s = summarize(payload)
    fleet = sorted(payload.get("fleet", []),
                   key=lambda x: -x.get("summary", {}).get("risk_score", 0))
    chips = "".join(
        f'<span class="chip" style="background:{_VERDICT_COLOR.get(v,"#666")}">{v}: '
        f'{_esc(s["verdicts"].get(v,0))}</span>'
        for v in ("BLOCK", "REVIEW", "PASS"))
    rows = ""
    for x in fleet:
        sm = x.get("summary", {})
        v = sm.get("verdict", "?")
        rows += (f'<tr><td>{_esc(x.get("sbc"))}</td><td>{_esc(x.get("vendor"))}</td>'
                 f'<td>{_esc(x.get("site"))}</td>'
                 f'<td style="color:{_VERDICT_COLOR.get(v,"#333")};font-weight:700">{_esc(v)}</td>'
                 f'<td>{_esc(sm.get("risk_score",0))}</td><td><code>{_esc(x.get("top"))}</code></td></tr>')
    top = "".join(f"<li><code>{_esc(c)}</code> &times;{_esc(n)}</li>"
                  for c, n in s["top_findings"]) or "<li>None</li>"
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SBC Fleet Executive Report</title><style>
 :root{{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}}
 body{{margin:0;background:#f5f6f8;color:#1a1a1a}} .wrap{{max-width:880px;margin:0 auto;padding:32px 24px 64px}}
 h1{{font-size:22px;margin:0 0 4px}} .sub{{color:#666;font-size:13px;margin-bottom:20px}}
 h2{{font-size:15px;margin:26px 0 10px}} .cards{{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}}
 .card{{background:#fff;border:1px solid #e6e8eb;border-radius:12px;padding:18px}}
 .big{{font-size:30px;font-weight:800}} .lbl{{color:#666;font-size:12px;margin-top:4px}}
 .chip{{color:#fff;font-size:12px;padding:3px 10px;border-radius:20px;margin-right:6px;display:inline-block}}
 table{{width:100%;border-collapse:collapse;background:#fff;border:1px solid #e6e8eb;border-radius:10px;overflow:hidden;font-size:13px}}
 th,td{{text-align:left;padding:9px 12px;border-bottom:1px solid #eef1f4}} th{{background:#fafbfc;font-size:11px;color:#666;text-transform:uppercase;letter-spacing:.04em}}
 code{{background:#f0f1f3;padding:1px 5px;border-radius:4px;font-size:12px}} ul{{padding-left:18px}}
 .foot{{margin-top:28px;font-size:11px;color:#999;text-align:center}}</style></head>
<body><div class="wrap">
 <h1>SBC Fleet Executive Report</h1>
 <div class="sub">Ruleset {_esc(s['ruleset_version'])} &middot; {_esc(s['total'])} SBCs &middot; {_esc(s['generated_at'])}</div>
 <div class="cards">
  <div class="card"><div class="big">{_esc(s['ca_ready'])}/{_esc(s['total'])}</div><div class="lbl">ready for the 2026 CA migration</div></div>
  <div class="card"><div class="big">{_esc(s['ca_not_ready'])}</div><div class="lbl">carry a TLS/CA/cert/SRTP blocker</div></div>
  <div class="card"><div class="big">{_esc(s['security_exposed'])}</div><div class="lbl">have an access-control exposure (domain S)</div></div>
 </div>
 <h2>Deploy verdicts</h2><div>{chips}</div>
 <h2>Fleet</h2>
 <table><thead><tr><th>SBC</th><th>Vendor</th><th>Site</th><th>Verdict</th><th>Risk</th><th>Top finding</th></tr></thead><tbody>{rows}</tbody></table>
 <h2>Most common high-severity findings</h2><ul>{top}</ul>
 <div class="foot">SBC Validator &middot; Metaventions AI &middot; the independent truth layer for real-time voice</div>
</div></body></html>"""
