#!/usr/bin/env bash
# One command to show the live dashboard, zero setup.
#
# Refreshes the canonical demo fleet, starts the local-first dashboard server, and
# opens the browser automatically. This is the logic behind both the `~/bin`
# launcher and the double-click "SBC Validator.command" on the Desktop, so there is
# ONE source of truth for "show me the dashboard".
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PORT="${1:-8787}"
cd "$REPO"

if [ ! -x ".venv/bin/sbc-validator" ]; then
  echo "First-time setup (creating the local environment, ~30s) ..."
  python3 -m venv .venv
  .venv/bin/pip install -q -e . >/dev/null
fi

# Fresh canonical 6-SBC fleet: clear any stale per-run output, then repopulate.
rm -rf results/* 2>/dev/null || true
.venv/bin/sbc-validator demo >/dev/null 2>&1 || true

URL="http://127.0.0.1:${PORT}/sbc_dashboard.html"
( sleep 1.5; open "$URL" >/dev/null 2>&1 ) &

echo ""
echo "  SBC Validator dashboard  ->  $URL"
echo "  (it just opened in your browser; close this window or press Ctrl-C to stop)"
echo ""
exec .venv/bin/sbc-validator serve --results results --port "$PORT"
