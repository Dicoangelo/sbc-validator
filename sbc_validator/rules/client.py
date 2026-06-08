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

_PINNED_PUBLIC_KEY_B64 is the publisher's PUBLIC key. The matching PRIVATE key
lives offline, outside this repo (default `~/.sbc-validator/keys/publisher_ed25519.pem`,
chmod 600), and is used only by the offline signer (tools/sign_ruleset.py). The
verifier never holds the private key. Migrate the private key to an HSM before GA.
The pin is a code constant on purpose: it is NOT environment-overridable, so a
hostile env cannot swap in an attacker key. Tests override it in-process with an
ephemeral key (see the `signing_key` fixture); they never need the real private key.
"""
from __future__ import annotations

import base64
import json
import os
import re
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)

DEFAULT_CACHE_DIR = Path(os.environ.get("SBC_RULE_CACHE", "~/.cache/sbc_validator")).expanduser()

# Pinned publisher public key (raw Ed25519, base64). Private half is offline,
# outside this repo. Rotate here (and re-sign rulesets) when the publisher key changes.
_PINNED_PUBLIC_KEY_B64 = "ws41rVVX8tKIKPWJDSZc8XS6y5oRTBXske1ufHiHky8="

# A signed bundle is small JSON; cap the inbound read so a hostile/runaway
# endpoint can't exhaust memory before we ever get to verify it.
_MAX_BUNDLE_BYTES = 8 * 1024 * 1024
# ruleset_id becomes a cache filename — keep it to a safe, traversal-proof charset.
_RULESET_ID_RE = re.compile(r"^[A-Za-z0-9._-]+$")


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


def _version(bundle: dict) -> str:
    return str(bundle.get("bundle_version") or "")


def _reject_rollback(bundle: dict, floor: str, source: str) -> None:
    """A signature proves authenticity, NOT freshness.

    The whole product promise is that the trust store gets checked against the
    *current* Microsoft root set. A validly-signed but STALE bundle (e.g. the
    pre-2026-06-07 list with the retired Baltimore root and no DigiCert G5) is
    still cryptographically valid — accepting it would silently tell customers
    to fix the wrong things. So a fetched bundle must be at least as new as the
    highest version we already trust (cached bundle or SBC_RULE_MIN_VERSION).
    bundle_version is an ISO date, so lexicographic compare == chronological.
    """
    if not floor:
        return
    nv = _version(bundle)
    if not nv or nv < floor:
        raise RuleVerificationError(
            f"rollback refused: rule bundle '{nv or 'unversioned'}' is older than the "
            f"trusted version '{floor}' ({source}). A signed-but-stale ruleset would "
            "screen against an out-of-date CA list."
        )


def load_private_key(path: str) -> Ed25519PrivateKey:
    return serialization.load_pem_private_key(Path(path).read_bytes(), password=None)


def sign_bundle(bundle: dict, private_key: Ed25519PrivateKey) -> dict:
    """Produce a signed bundle (used by the offline signer / tests)."""
    out = {k: v for k, v in bundle.items() if k != "signature"}
    out["signature"] = base64.b64encode(private_key.sign(_canonical(out))).decode()
    return out


class RuleClient:
    def __init__(self, api_base: Optional[str] = None, cache_dir: Path = DEFAULT_CACHE_DIR,
                 fetcher=None, timeout: float = 10.0):
        self.api_base = api_base
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        # fetcher(url) -> bytes. Injectable so the transport is testable offline.
        self._fetch_bytes = fetcher or self._http_get
        self.timeout = timeout

    def _cache_path(self, ruleset_id: str) -> Path:
        if not _RULESET_ID_RE.match(ruleset_id):
            raise RuleVerificationError(f"unsafe ruleset id: {ruleset_id!r}")
        return self.cache_dir / f"{ruleset_id}.json"

    def _trusted_floor(self, ruleset_id: str) -> str:
        """Highest version we already trust: env pin vs. the verified cache."""
        floor = os.environ.get("SBC_RULE_MIN_VERSION", "")
        cache = self._cache_path(ruleset_id)
        if cache.exists():
            try:
                cached_v = _version(json.loads(cache.read_text()))
                floor = max(floor, cached_v)
            except (ValueError, OSError):
                pass
        return floor

    def _http_get(self, url: str) -> bytes:
        """Default transport: a plain stdlib HTTPS GET (no third-party deps).

        The rule channel is the one thing crossing into the trust boundary, so
        the default transport refuses anything but HTTPS. An operator running an
        air-gapped internal mirror can opt into http/file with SBC_RULE_ALLOW_INSECURE=1
        (the signature + rollback checks still run regardless of transport).
        """
        scheme = (urlparse(url).scheme or "").lower()
        if scheme != "https" and os.environ.get("SBC_RULE_ALLOW_INSECURE") != "1":
            raise RuleVerificationError(
                f"refusing non-HTTPS rule transport ({scheme or 'no'}-scheme). "
                "Set SBC_RULE_ALLOW_INSECURE=1 only for a trusted air-gapped mirror."
            )
        import urllib.request
        with urllib.request.urlopen(url, timeout=self.timeout) as resp:  # noqa: S310
            data = resp.read(_MAX_BUNDLE_BYTES + 1)
        if len(data) > _MAX_BUNDLE_BYTES:
            raise RuleVerificationError(
                f"rule bundle exceeds {_MAX_BUNDLE_BYTES} bytes — refusing oversized payload"
            )
        return data

    def fetch(self, ruleset_id: str, local_path: Optional[str] = None) -> dict:
        """
        Return a verified rule bundle.

        Resolution order:
          1. explicit local_path (offline / air-gapped operation)
          2. remote API (self.api_base) over the injectable transport
          3. last cached verified bundle (with a freshness warning)

        Rule bundles are the ONLY inbound channel and are treated as
        untrusted-until-verified: whatever the source, the Ed25519 signature is
        checked against the pinned key BEFORE the bundle is cached or used.
        """
        floor = self._trusted_floor(ruleset_id)

        if local_path:
            bundle = json.loads(Path(local_path).read_text())
            _verify(bundle)
            _reject_rollback(bundle, floor, f"local_path {local_path}")
            self._cache_path(ruleset_id).write_text(json.dumps(bundle))
            return bundle

        if self.api_base:
            url = f"{self.api_base.rstrip('/')}/rulesets/{ruleset_id}/latest"
            try:
                raw = self._fetch_bytes(url)
                bundle = json.loads(raw)
                _verify(bundle)                 # verify BEFORE trusting/caching
                _reject_rollback(bundle, floor, "remote")  # freshness, not just authenticity
            except RuleVerificationError:
                raise                           # tampered or stale: never fall back silently
            except Exception:
                bundle = None                   # network/parse failure -> try cache
            if bundle is not None:
                self._cache_path(ruleset_id).write_text(json.dumps(bundle))
                return bundle

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
