#!/usr/bin/env bash
# End-to-end acceptance test: exercise the SHIPPED artifact exactly as a customer
# gets it. Builds the wheel, installs it into a pristine venv (no repo on the
# path), then runs every user-facing command from a clean working dir that holds
# only configs + a ruleset. Isolated from the real rule cache. Pre-pilot smoke.
#
#   bash scripts/acceptance.sh
#
# Exits non-zero if any check fails.
set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
export SBC_RULE_CACHE="$WORK/cache"          # do not touch the user's real cache
RS="rulesets/ms_direct_routing_2026-06.json"
PASS=0; FAIL=0
ok(){ printf '  \033[32mPASS\033[0m  %s\n' "$1"; PASS=$((PASS+1)); }
no(){ printf '  \033[31mFAIL\033[0m  %s\n' "$1"; FAIL=$((FAIL+1)); }
trap 'rm -rf "$WORK"' EXIT

echo "== building + installing the wheel into a clean venv =="
python3 -m pip wheel "$REPO" -w "$WORK/wheel" --no-deps -q
python3 -m venv "$WORK/venv"
"$WORK/venv/bin/pip" install -q "$WORK"/wheel/*.whl cryptography
SBC="$WORK/venv/bin/sbc-validator"
[ -x "$SBC" ] && ok "clean install: sbc-validator entrypoint present" || { no "entrypoint missing"; exit 1; }

# customer working dir: only configs + a ruleset, NOT the repo
mkdir -p "$WORK/cust/samples" "$WORK/cust/rulesets"
cp "$REPO"/samples/* "$WORK/cust/samples/" 2>/dev/null
cp "$REPO"/rulesets/*.json "$WORK/cust/rulesets/"
cd "$WORK/cust"

echo "== command surface =="
"$SBC" --help >/dev/null 2>&1 && ok "help" || no "help"

echo "== demo (the showcase a prospect runs) =="
"$SBC" demo >"$WORK/demo.out" 2>&1
grep -q "2026 CA readiness" "$WORK/demo.out" && ok "demo runs end-to-end" || no "demo"
grep -q "NO_CONNECT" "$WORK/demo.out" && ok "demo: predicts NO_CONNECT at TLS" || no "demo predict"
grep -q "REJECTED_488" "$WORK/demo.out" && ok "demo: explains 488 capture" || no "demo explain"

echo "== validate verdicts + exit codes (the CI gate contract) =="
"$SBC" validate samples/clean_pass.ini --ruleset "$RS" >/dev/null 2>&1
[ $? -eq 0 ] && ok "clean config -> PASS, exit 0" || no "clean exit code"
"$SBC" validate samples/audiocodes_min.ini --ruleset "$RS" >/dev/null 2>&1
[ $? -ne 0 ] && ok "missing-root-CA -> BLOCK, exit !=0 (gates a pipeline)" || no "block exit code"
"$SBC" validate samples/review_high.ini --ruleset "$RS" --fail-on review >/dev/null 2>&1
[ $? -ne 0 ] && ok "--fail-on review gates a REVIEW" || no "fail-on review"

echo "== other modes =="
"$SBC" simulate samples/audiocodes_min.ini --ruleset "$RS" 2>&1 | grep -q "NO_CONNECT" && ok "simulate predicts the call" || no "simulate"
"$SBC" explain samples/reject_488.pcap 2>&1 | grep -qi "488" && ok "explain reconstructs the capture" || no "explain"
# capture first: diff/fleet exit non-zero by design (BLOCK / not-ready), which
# under `pipefail` would mask a matching grep.
dout=$("$SBC" diff samples/clean_pass.ini samples/audiocodes_standby.ini 2>&1) || true
echo "$dout" | grep -qi "drift" && ok "diff detects HA drift" || no "diff"
fout=$("$SBC" fleet samples --ruleset "$RS" 2>&1) || true
echo "$fout" | grep -qi "ready" && ok "fleet readiness rollup" || no "fleet"

echo "== robustness (must never spill a traceback) =="
printf '@@@ not any vendor @@@\n' > bad.ini
"$SBC" validate bad.ini --ruleset "$RS" >out.txt 2>&1; rc=$?
{ ! grep -qi "traceback" out.txt; } && [ $rc -eq 2 ] && ok "malformed config -> clean exit 2" || no "malformed config (rc=$rc)"

echo "== trust channel (a bad ruleset must be refused cleanly, not crash) =="
python3 - "$RS" <<'PY'
import json, sys
p = sys.argv[1]
b = json.loads(open(p).read())
b["C"]["cert_expiry_warn_days"] = 9999          # tamper after signing
open("tampered.json", "w").write(json.dumps(b))
PY
"$SBC" validate samples/clean_pass.ini --ruleset tampered.json >tout.txt 2>&1; rc=$?
{ ! grep -qi "traceback" tout.txt; } && [ $rc -ne 0 ] && grep -qi "signature\|refus\|invalid" tout.txt \
  && ok "tampered ruleset refused cleanly" || no "tampered ruleset (rc=$rc): $(head -1 tout.txt)"

echo "== local dashboard server =="
"$SBC" serve --results results --port 8791 >/dev/null 2>&1 &
SVPID=$!; sleep 2
curl -sf -o /dev/null "http://127.0.0.1:8791/sbc_dashboard.html" && ok "serve: dashboard reachable" || no "serve html"
n=$(curl -sf "http://127.0.0.1:8791/dashboard_data.json" | python3 -c "import sys,json;print(len(json.load(sys.stdin)['fleet']))" 2>/dev/null)
[ "${n:-0}" -ge 4 ] && ok "serve: live payload (${n:-0} SBCs)" || no "serve json (${n:-0})"
kill $SVPID 2>/dev/null

echo
echo "================ ACCEPTANCE: $PASS passed, $FAIL failed ================"
[ $FAIL -eq 0 ]
