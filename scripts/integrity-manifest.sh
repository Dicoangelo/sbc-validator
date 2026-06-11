#!/usr/bin/env bash
# Generate SHA256SUMS over every git-tracked source file, so a design partner
# can verify the tree they received before building it:
#
#   sha256sum -c SHA256SUMS
#
# Run from the repo root before cutting a design-partner delivery.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
# include untracked-but-not-ignored files, skip index entries deleted on disk
# (otherwise running before `git add` of deletions/additions breaks the manifest)
git ls-files -z --cached --others --exclude-standard | grep -zv '^SHA256SUMS$' | \
  while IFS= read -r -d '' f; do [ -f "$f" ] && printf '%s\0' "$f"; done | \
  xargs -0 shasum -a 256 > SHA256SUMS
echo "wrote SHA256SUMS ($(wc -l < SHA256SUMS | tr -d ' ') files)"
