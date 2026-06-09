#!/usr/bin/env bash
# Rebuild the entire Philip review packet from the repo, in one command.
#
# The packet on the Desktop is a DERIVED artifact, never hand-assembled: this
# regenerates the source tarball, every PDF, and the fleet report from the current
# repo HEAD. Run it whenever the repo changes and the handoff needs to be current.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PKT="$HOME/Desktop/SBC Philip Review"
cd "$REPO"
mkdir -p "$PKT"

HASH="$(git rev-parse --short HEAD)"
echo "Rebuilding review packet from $REPO @ $HASH ..."

# 1. Source tarball at the reviewed commit (replace any older one).
rm -f "$PKT"/sbc_validator_*.tar.gz
git archive --format=tar.gz --prefix=sbc-validator/ \
  -o "$PKT/sbc_validator_${HASH}.tar.gz" HEAD
echo "  tarball:  sbc_validator_${HASH}.tar.gz"

# 2. Render every handoff doc to PDF.
for d in REVIEW REVIEW-FINDINGS ARCHITECTURE ONE-PAGER MEETING-QA CONFIG-REQUEST VALIDATOR-COVERAGE; do
  pandoc "docs/$d.md" -o "$PKT/$d.pdf" --pdf-engine=weasyprint 2>/dev/null
  echo "  pdf:      $d.pdf"
done

# 3. Fresh, canonical fleet report (clean 6-SBC run -> HTML + PDF).
rm -rf results/* 2>/dev/null || true
.venv/bin/sbc-validator demo >/dev/null 2>&1
.venv/bin/sbc-validator report --results results --out "$PKT/SBC_Fleet_Report.html" >/dev/null
pandoc "$PKT/SBC_Fleet_Report.html" -o "$PKT/SBC_Fleet_Report.pdf" --pdf-engine=weasyprint 2>/dev/null
echo "  report:   SBC_Fleet_Report.{html,pdf}"

echo ""
echo "Done. Packet rebuilt at: $PKT  (commit $HASH)"
echo "Note: _READ-ME-FIRST.md and AGENDA.md are edited by hand (narrative); update the"
echo "version stamp there if the release changed."
