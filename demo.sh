#!/usr/bin/env bash
# Turnkey demo: validate the full sample fleet (AudioCodes + Cisco CUBE),
# emit a customer HTML report per SBC, build the dashboard payload, and print
# the fleet verdict table. Everything runs locally; no network, no config egress.
#
#   ./demo.sh
#
set -euo pipefail
cd "$(dirname "$0")"

RULESET="rulesets/ms_direct_routing_2026-06.json"
OUT="results"
REPORTS="reports"
PY="${PYTHON:-python}"

rm -rf "$OUT" "$REPORTS"
mkdir -p "$REPORTS"

# sample : site  (mixed vendors, mixed verdicts)
run () {  # $1 config  $2 sbc-label  $3 site
  "$PY" -m sbc_validator.cli validate "$1" \
      --ruleset "$RULESET" --out "$OUT" --site "$3" \
      --html "$REPORTS/$2.html" >/dev/null || true   # BLOCK returns non-zero; keep going
  echo "  validated $1  ->  $REPORTS/$2.html"
}

echo "== validating fleet (3 vendors) =="
run samples/clean_pass.ini      sbc05_fabrikam   EU-West   # AudioCodes
run samples/review_high.ini     sbc09_northwind  US-East   # AudioCodes
run samples/broken_a.ini        broken_a         DR-Site   # AudioCodes
run samples/audiocodes_min.ini  sbc01_contoso    EU-West   # AudioCodes
run samples/cisco_cube_dr.txt   cube_sbc_01      US-West   # Cisco CUBE
run samples/ribbon_sbc.cli      sbc_ribbon_01    EU-West   # Ribbon

echo "== building dashboard payload =="
"$PY" -m sbc_validator.tools.build_dashboard_data "$OUT" -o dashboard_data.json

echo "== fleet verdicts =="
"$PY" - <<'PYEOF'
import json
d = json.load(open("dashboard_data.json"))
print(f"  ruleset {d['ruleset_version']}   mode {d['mode']}   {len(d['fleet'])} SBCs")
for x in sorted(d["fleet"], key=lambda r: r["summary"]["risk_score"], reverse=True):
    s = x["summary"]
    print(f"  {x['sbc']:24} {x['vendor']:11} {x.get('site',''):8} "
          f"{s['verdict']:7} risk={s['risk_score']:>3}  top={x['top']}")
PYEOF

echo
echo "== HA drift check (active vs standby) =="
"$PY" -m sbc_validator.cli diff samples/clean_pass.ini samples/audiocodes_standby.ini || true

echo
echo "Done. Open sbc_dashboard.html (Load dashboard_data.json) and reports/*.html"
