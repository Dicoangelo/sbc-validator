"""
Pull a signed rule bundle from the central rule service into the local cache.

    python -m sbc_validator.tools.fetch_ruleset https://rules.example.com ms_direct_routing
    python -m sbc_validator.tools.fetch_ruleset <api_base> <ruleset_id> -o local.json

The bundle's Ed25519 signature is verified against the pinned publisher key
before it is written. This is the only inbound channel; configs never travel it.
Keeping fetch a separate step lets `validate` stay offline/air-gapped: pull the
latest signed rules here, then point `validate --ruleset` at the cached file.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from ..rules.client import RuleClient, RuleVerificationError


def main(argv=None) -> int:
    argv = argv or sys.argv[1:]
    out = None
    if "-o" in argv:
        i = argv.index("-o")
        out = argv[i + 1]
        argv = argv[:i] + argv[i + 2:]
    if len(argv) != 2:
        print("usage: fetch_ruleset <api_base> <ruleset_id> [-o out.json]", file=sys.stderr)
        return 2
    api_base, ruleset_id = argv
    client = RuleClient(api_base=api_base)
    try:
        bundle = client.fetch(ruleset_id)
    except RuleVerificationError as e:
        print(f"refused: {e}", file=sys.stderr)
        return 1
    dest = Path(out) if out else client._cache_path(ruleset_id)
    dest.write_text(json.dumps(bundle, indent=2))
    print(f"fetched + verified '{ruleset_id}' (version {bundle.get('bundle_version')}) -> {dest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
