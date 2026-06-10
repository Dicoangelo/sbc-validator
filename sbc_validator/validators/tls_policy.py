"""
Domain C — TLS protocol-version and cipher-suite policy.

The signed ruleset's C block carries Microsoft Direct Routing's transport floor
(`tls_min_version`) and its accepted SIP-TLS cipher allowlist
(`allowed_sip_cipher_suites`). Those facts were defined in the bundle but never
enforced against the config — a rule we shipped and never checked. This closes
that gap.

Both checks are tristate-safe: they fire ONLY when the source actually carried a
version floor / cipher list (model field is not None). A config that does not
express TLS version or ciphers produces no finding, never a false BLOCK.
"""
from __future__ import annotations

import re

from ..models import TlsContext
from .base import Finding, Severity


def _canon_cipher(s: str) -> str:
    """Canonicalize a cipher name so IANA and OpenSSL spellings compare equal.

    'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384' and 'ECDHE-RSA-AES256-GCM-SHA384'
    both collapse to 'ecdhersaaes256gcmsha384'. We strip the IANA-only 'TLS' and
    'WITH' decorations and every separator, leaving the cryptographic primitives.
    """
    t = re.sub(r"[^a-z0-9]", "", str(s or "").lower())
    return t.replace("tls", "").replace("with", "")


def _ver_tuple(s):
    """'1.2' -> (1, 2); None / unparseable -> None."""
    m = re.search(r"(\d+)\.(\d+)", str(s or ""))
    return (int(m.group(1)), int(m.group(2))) if m else None


def tls_policy_findings(ctx: TlsContext, rules: dict) -> list[Finding]:
    out: list[Finding] = []
    loc = f"TlsContext '{ctx.name}'"

    # --- minimum TLS version floor ---
    req = _ver_tuple(rules.get("tls_min_version"))
    have = _ver_tuple(ctx.min_tls_version)
    if req and have and have < req:
        out.append(Finding(
            check_id="C.TLS.WEAK_VERSION",
            title=f"TLS floor {ctx.min_tls_version} is below the required "
                  f"{rules.get('tls_min_version')}",
            severity=Severity.HIGH,
            detail="Microsoft Direct Routing negotiates TLS 1.2 or higher. An SBC "
                   "that still accepts TLS 1.0/1.1 is exposed to downgrade and will "
                   "be refused once the platform drops the legacy floor.",
            remediation=f"Raise the TLS context minimum protocol to "
                        f"{rules.get('tls_min_version')} or higher.",
            locator=loc,
        ))

    # --- cipher-suite allowlist ---
    allowed = rules.get("allowed_sip_cipher_suites")
    if allowed and ctx.cipher_suites is not None:
        allow_canon = {_canon_cipher(c) for c in allowed}
        offered = ctx.cipher_suites
        overlap = [c for c in offered if _canon_cipher(c) in allow_canon]
        # The handshake succeeds if ANY cipher is mutually accepted (the platform
        # picks the strongest). So the hard-stop case is zero overlap; a config
        # that includes at least one accepted suite still connects.
        if offered and not overlap:
            out.append(Finding(
                check_id="C.TLS.CIPHER_NOT_ALLOWED",
                title="No configured cipher suite is accepted by Direct Routing",
                severity=Severity.CRITICAL,
                detail="None of the SBC's configured SIP-TLS cipher suites are on "
                       "Microsoft's accepted list, so the handshake has no common "
                       "cipher and hard-fails. Configured: " + ", ".join(offered),
                remediation="Add at least one accepted ECDHE-RSA AES-GCM/CBC SHA-2 "
                            "suite (see the ruleset's allowed_sip_cipher_suites).",
                locator=loc,
            ))
    return out
