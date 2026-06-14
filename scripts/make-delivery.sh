#!/usr/bin/env bash
# Build the design-partner source delivery: engine + samples + customer docs ONLY.
# Never includes marketing/, business/ (GTM, meeting kits), or internal docs.
# The archive carries its own SHA256SUMS regenerated for exactly the delivered tree.
#
#   ./scripts/make-delivery.sh v0.16.2 [outdir]
set -euo pipefail
TAG="${1:?usage: make-delivery.sh <tag> [outdir]}"
OUT="${2:-$HOME/Desktop/SBC-Delivery}"
VER="${TAG#v}"
cd "$(git rev-parse --show-toplevel)"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

git archive --prefix="sbc-validator-${VER}/" "$TAG" \
  sbc_validator rulesets samples tests examples README.md EVALUATOR-START-HERE.md pyproject.toml Dockerfile .dockerignore demo.sh \
  docs/SECURITY.md docs/ARCHITECTURE.md docs/RUNBOOK.md docs/DOMAIN_REFERENCE.md docs/CONFIG-REQUEST.md \
  docs/VALIDATOR-COVERAGE.md docs/RULE_AUTHORITY.md docs/PRE-COMMIT-CONTROL.md docs/sbom-cyclonedx.json \
  | tar -x -C "$WORK"

( cd "$WORK/sbc-validator-${VER}" \
  && find . -type f ! -name SHA256SUMS | sed 's|^\./||' | sort | xargs shasum -a 256 > SHA256SUMS )

mkdir -p "$OUT"
tar -czf "$OUT/sbc-validator-${VER}-src.tar.gz" -C "$WORK" "sbc-validator-${VER}"
shasum -a 256 "$OUT/sbc-validator-${VER}-src.tar.gz" | tee "$OUT/sbc-validator-${VER}-src.tar.gz.sha256"
echo "delivery: $OUT/sbc-validator-${VER}-src.tar.gz ($(du -h "$OUT/sbc-validator-${VER}-src.tar.gz" | cut -f1))"
