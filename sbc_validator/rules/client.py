"""
Rule-set client.

Design note (addresses the trust-surface risk in the PRD review):
rule bundles are the ONE thing that crosses into the trust boundary, so they
are treated as untrusted-until-verified:

  * every bundle is VERSIONED (bundle_version + issued_at)
  * every bundle is SIGNED with Ed25519; we verify against a PINNED publisher
    public key before use
  * the verified version is stamped into every report ("freshness assertion")
  * if the network is unavailable we fall back to the last cached *verified*
    bundle and downgrade confidence, rather than silently running on nothing

Configs never travel this channel. Only rules come IN.

The pinned key below is a DEV key (matching dev/dev_signing_key.pem). In
production, replace _PINNED_PUBLIC_KEY_B64 with your real publisher key and keep
the private key in an offline signer / HSM.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)

DEFAULT_CACHE_DIR = Path(os.environ.get("SBC_RULE_CACHE", "~/.cache/sbc_validator")).expanduser()

# Pinned publisher public key (raw Ed25519, base64). DEV value — replace in prod.
_PINNED_PUBLIC_KEY_B64 = "2b+tAmJiIbYfoMbHj7K2hn1YkyWnCZehbPdJJwmeHwk="


class RuleVerificationError(RuntimeError):
    pass


def _canonical(bundle: dict) -> bytes:
    body = {k: v for k, v in bundle.items() if not k.startswith("_") and k != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def _pinned_pubkey() -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(base64.b64decode(_PINNED_PUBLIC_KEY_B64))


def _verify(bundle: dict) -> None:
    sig_b64 = bundle.get("signature")
    if not sig_b64:
        raise RuleVerificationError("rule bundle is unsigned")
    try:
        _pinned_pubkey().verify(base64.b64decode(sig_b64), _canonical(bundle))
    except (InvalidSignature, ValueError) as e:
        raise RuleVerificationError("rule bundle signature invalid — refusing to use") from e


def load_private_key(path: str) -> Ed25519PrivateKey:
    return serialization.load_pem_private_key(Path(path).read_bytes(), password=None)


def sign_bundle(bundle: dict, private_key: Ed25519PrivateKey) -> dict:
    """Produce a signed bundle (used by the offline signer / tests)."""
    out = {k: v for k, v in bundle.items() if k != "signature"}
    out["signature"] = base64.b64encode(private_key.sign(_canonical(out))).decode()
    return out


class RuleClient:
    def __init__(self, api_base: Optional[str] = None, cache_dir: Path = DEFAULT_CACHE_DIR):
        self.api_base = api_base
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _cache_path(self, ruleset_id: str) -> Path:
        return self.cache_dir / f"{ruleset_id}.json"

    def fetch(self, ruleset_id: str, local_path: Optional[str] = None) -> dict:
        """
        Return a verified rule bundle.

        Resolution order:
          1. explicit local_path (offline / air-gapped operation)
          2. remote API (not implemented in skeleton — wire your transport here)
          3. last cached verified bundle
        """
        if local_path:
            bundle = json.loads(Path(local_path).read_text())
            _verify(bundle)
            self._cache_path(ruleset_id).write_text(json.dumps(bundle))
            return bundle

        # --- remote fetch would go here ---
        # resp = http_get(f"{self.api_base}/rulesets/{ruleset_id}/latest")
        # bundle = resp.json(); _verify(bundle); cache; return bundle

        cached = self._cache_path(ruleset_id)
        if cached.exists():
            bundle = json.loads(cached.read_text())
            _verify(bundle)
            bundle.setdefault("_warnings", []).append(
                "served from cache; remote freshness not confirmed"
            )
            return bundle

        raise RuleVerificationError(
            f"no verified ruleset '{ruleset_id}' available (no local_path, no cache)"
        )
