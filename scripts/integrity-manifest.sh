#!/usr/bin/env bash
# Generate SHA256SUMS over every git-tracked source file, so a design partner
# can verify the tree they received before building it:
#
#   sha256sum -c SHA256SUMS
#
# Run from the repo root before cutting a design-partner delivery.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
git ls-files -z | grep -zv '^SHA256SUMS$' | xargs -0 shasum -a 256 > SHA256SUMS
echo "wrote SHA256SUMS ($(wc -l < SHA256SUMS | tr -d ' ') files)"
