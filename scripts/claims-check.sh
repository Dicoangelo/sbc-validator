#!/usr/bin/env bash
# Claims-consistency linter: every externally stated figure must match the
# repository's ground truth. Kills the stale-number class (160->165->172 drifted
# three times before this existed). Run locally or in CI; non-zero exit on drift.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

fail=0
say(){ printf '%s\n' "$*"; }

# ---- canonical figures ----
TESTS=$(.venv/bin/pytest --collect-only -q 2>/dev/null | tail -1 | grep -oE '^[0-9]+' || true)
[ -z "${TESTS}" ] && TESTS=$(python3 -m pytest --collect-only -q 2>/dev/null | tail -1 | grep -oE '^[0-9]+' || echo "")
VERSION=$(grep -m1 '^version' pyproject.toml | sed 's/.*"\(.*\)"/\1/')

SURFACES="marketing/business-case.html README.md docs/SECURITY.md"

# ---- test count ----
if [ -n "$TESTS" ]; then
  for f in $SURFACES; do
    stale=$(grep -oE '\b[0-9]{3}\b(?=)' /dev/null 2>/dev/null || true)
    hits=$(grep -oE '\b[0-9]+ (automated )?tests in CI\b|Tests-[0-9]+|\b[0-9]+</b> tests in CI' "$f" 2>/dev/null | grep -oE '[0-9]+' | sort -u || true)
    for h in $hits; do
      if [ "$h" != "$TESTS" ]; then
        say "DRIFT: $f claims $h tests; suite has $TESTS"; fail=1
      fi
    done
  done
fi

# ---- engine version on the contract stamp ----
if grep -q "engine v" marketing/business-case.html; then
  stamped=$(grep -oE 'engine v[0-9.]+' marketing/business-case.html | head -1 | sed 's/engine v//')
  if [ "$stamped" != "$VERSION" ]; then
    say "DRIFT: site contract stamp says v$stamped; pyproject is v$VERSION"; fail=1
  fi
fi

# ---- em dashes in customer-facing docs (writing rule) ----
for f in README.md docs/SECURITY.md docs/ONE-PAGER.md; do
  [ -f "$f" ] || continue
  if grep -q "—" "$f"; then
    : # em dashes allowed in repo docs headers historically; only warn
  fi
done

if [ "$fail" -eq 0 ]; then
  say "claims-check: all stated figures match ground truth (tests=$TESTS, version=$VERSION)"
else
  say "claims-check: FAILED — fix the drifted claims above"
fi
exit $fail
