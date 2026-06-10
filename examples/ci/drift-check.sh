#!/usr/bin/env bash
# Golden-config drift tripwire: compare today's SBC export against the
# last-known-good and alert on ANY drift finding.
#
# This is the scheduled (cron/CI) use of `sbc-validator diff` — no daemon, no
# agent on the SBC. You export the config the way you already do (vendor
# backup job, REST pull, SCP); this script answers "did anything
# failover-critical change since the config we signed off?".
#
#   ./drift-check.sh golden/sbc-teams-01.ini exports/sbc-teams-01-today.ini
#
# Cron example (daily 06:00, mail on drift):
#   0 6 * * * /opt/sbc/drift-check.sh /opt/sbc/golden/teams01.ini /opt/sbc/exports/teams01.ini \
#       || mail -s "SBC drift detected" voice-team@example.com < /tmp/sbc-drift.txt
set -euo pipefail

GOLDEN="${1:?usage: drift-check.sh <golden-config> <current-export>}"
CURRENT="${2:?usage: drift-check.sh <golden-config> <current-export>}"

# --fail-on any: ANY drift finding exits non-zero (the tripwire), not just BLOCK.
if sbc-validator diff "$GOLDEN" "$CURRENT" --fail-on any | tee /tmp/sbc-drift.txt; then
  echo "OK: current export matches the last-known-good on all failover-critical fields."
else
  echo "DRIFT: review /tmp/sbc-drift.txt — then either remediate the SBC or, if the"
  echo "change was intended, validate it and promote the export to the new golden:"
  echo "  sbc-validator validate '$CURRENT' --fail-on review && cp '$CURRENT' '$GOLDEN'"
  exit 1
fi
