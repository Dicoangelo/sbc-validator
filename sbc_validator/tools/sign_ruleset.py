"""
Offline rule-bundle signer.

    python -m sbc_validator.tools.sign_ruleset <bundle.json> <private_key.pem>

Writes the signed bundle back in place. Keep the private key offline / in an HSM
in production. The verifier (rules/client.py) only ever holds the public key.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from ..rules.client import load_private_key, sign_bundle


def main(argv=None) -> int:
    argv = argv or sys.argv[1:]
    if len(argv) != 2:
        print("usage: sign_ruleset <bundle.json> <private_key.pem>", file=sys.stderr)
        return 2
    bundle_path, key_path = argv
    bundle = json.loads(Path(bundle_path).read_text())
    signed = sign_bundle(bundle, load_private_key(key_path))
    Path(bundle_path).write_text(json.dumps(signed, indent=2))
    print(f"signed {bundle_path} (version {signed.get('bundle_version')})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
