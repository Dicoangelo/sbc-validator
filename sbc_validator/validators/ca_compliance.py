"""
Domain C — TLS / SRTP & CA Compliance (primary wedge).

Encodes the Microsoft Direct Routing 2026 mTLS/CA requirements as logic driven
by a pulled rule bundle (so the authoritative root-CA list and counts live in
the signed ruleset, not hardcoded here). Requirements sourced from Microsoft
Learn and verified 2026-06-07 (see docs/RULE_AUTHORITY.md):

  * SBC trust store must contain ALL 7 required Microsoft/DigiCert root CAs
    (incl. the new DigiCert TLS ECC/RSA Root G5 pair) for the Teams mTLS context.
  * SBC leaf certificate must include the Server Authentication EKU.
    Dual-use / clientAuth-only server certs are being deprecated -> warn.
  * Leaf CN/SAN must match the SBC FQDN presented to Teams.
  * Leaf must not be expired or expiring inside the ruleset's warn window.
  * mTLS should be enabled on the Teams SIP interface.

Failure mode this prevents: a hard TLS handshake stop where calls don't connect
and nothing in Teams points at the cert — the classic "scream test".
"""
from __future__ import annotations

import re

from ..models import NormalizedConfig
from .base import AbstractValidator, Finding, Severity, ValidatorResult
# Leaf-cert logic lives in cert_checks; the name helpers are re-exported here
# because tests (and the module's historical API) import them from this module.
from .cert_checks import _fqdn_matches, _name_covers, leaf_cert_findings  # noqa: F401
from .tls_policy import tls_policy_findings


def _ver_lt(a: str, b: str) -> bool:
    """Numeric dotted-version compare: '17.6.1a' < '26.1.1'. Non-numeric suffixes
    are ignored per segment; unparseable versions compare False (judge nothing)."""
    def parts(v):
        out = []
        for seg in str(v).split("."):
            m = re.match(r"(\d+)", seg)
            if not m:
                break
            out.append(int(m.group(1)))
        return out
    pa, pb = parts(a), parts(b)
    return bool(pa and pb) and pa < pb


def _norm(s) -> str:
    """Normalize a CA identifier for tolerant matching: lowercase, strip every
    non-alphanumeric, and fold the 'Certificate Authority' <-> 'CA' synonym. So
    'Microsoft ECC Root Certificate Authority 2017' and 'MicrosoftECCRootCA2017'
    compare equal, as do 'DigiCert Global Root G2' / 'DigiCertGlobalRootG2'; SHA-1
    thumbprints compare with or without colons/spaces."""
    n = re.sub(r"[^a-z0-9]", "", str(s or "").lower())
    return n.replace("certificateauthority", "ca")


class CaComplianceValidator(AbstractValidator):
    domain = "C"

    def validate(self, config: NormalizedConfig) -> ValidatorResult:
        res = ValidatorResult(domain=self.domain)
        rules = self.ruleset.get("C", {})
        required_roots = rules.get("required_root_ca_ids", [])
        warn_days = rules.get("cert_expiry_warn_days", 30)

        teams = config.teams_interface()
        if teams is None:
            res.add(Finding(
                check_id="C.IFACE.NO_TEAMS",
                title="No Teams-facing SIP interface identified",
                severity=Severity.MEDIUM,
                detail="No SIP interface was normalized with role='teams'. "
                       "Direct Routing CA checks cannot be applied.",
                remediation="Confirm the parser tagged the Teams SIP interface, "
                            "or set its role explicitly.",
            ))
            return res

        ctx = teams.tls_context
        if ctx is None:
            res.add(Finding(
                check_id="C.TLS.NO_CONTEXT",
                title="Teams interface has no TLS context",
                severity=Severity.CRITICAL,
                detail="Direct Routing requires mTLS; no TLS profile is bound.",
                remediation="Bind a TLS context to the Teams SIP interface.",
                locator=f"iface '{teams.name}'",
            ))
            return res

        # --- mTLS enabled --- (fire only when the source says it is OFF, not unknown)
        if ctx.mtls_enabled is False:
            res.add(Finding(
                check_id="C.TLS.MTLS_DISABLED",
                title="mTLS not enabled on Teams interface",
                severity=Severity.HIGH,
                detail="Microsoft DR uses mutual TLS; without it the 2026 root-CA "
                       "trust requirements aren't exercised and handshakes may fail.",
                remediation="Enable mutual TLS on the Teams SIP TLS context.",
                locator=f"TlsContext '{ctx.name}'",
            ))

        # --- SRTP media encryption (Teams DR requires encrypted media) ---
        if teams.srtp_enabled is False:
            res.add(Finding(
                check_id="C.SRTP.DISABLED",
                title="SRTP not enabled on the Teams media leg",
                severity=Severity.HIGH,
                detail="Microsoft Direct Routing requires encrypted media (SRTP, "
                       "offered as SDP a=crypto). Without it Teams will not establish "
                       "media and the call has no audio.",
                remediation="Enable SRTP on the Teams leg with the "
                            "AES_CM_128_HMAC_SHA1_80 crypto suite.",
                locator=f"iface '{teams.name}'",
            ))

        # --- TLS version floor + cipher allowlist (ruleset-driven) ---
        # Enforces the bundle's tls_min_version + allowed_sip_cipher_suites, which
        # were defined but previously unchecked. Tristate-safe (silent on unknown).
        res.findings.extend(tls_policy_findings(ctx, rules))

        # --- required root CAs present (count + identity) ---
        # The ruleset lists each required root as {"name", "sha1"} (authoritative,
        # sourced — see docs/RULE_AUTHORITY.md). Older bundles may list plain name
        # strings; both are handled. Matching is naming-tolerant: configs name the
        # same root inconsistently ("DigiCert Global Root G2" vs "DigiCertGlobalRootG2"),
        # so we compare on a normalized form and also accept a SHA-1 thumbprint match.
        present_norm = {_norm(p) for p in ctx.trusted_root_ids}
        if not present_norm and not ctx.introspectable:
            # The source references a trust store that is imported separately (e.g.
            # an AudioCodes .ini, where root CAs are certificate files, not config
            # text). We genuinely cannot enumerate it: say so rather than false-claim
            # every root is missing.
            res.add(Finding(
                check_id="C.CA.TRUST_STORE_UNAVAILABLE",
                title="Trust store not present in this config source",
                severity=Severity.LOW,
                detail="The Teams TLS context lists no root CAs. On exports where the "
                       "trust store is imported separately (e.g. AudioCodes .ini), this "
                       "is expected; the 7 required 2026 root CAs must be verified "
                       "out-of-band.",
                remediation="Confirm the Teams TLS trust store contains all 7 required "
                            "root CAs (see docs/RULE_AUTHORITY.md), or supply trusted-root ids.",
                locator=f"TlsContext '{ctx.name}'",
            ))
            required_roots = []      # skip the per-root missing check below
        # If present_norm is empty but the context IS introspectable, the source
        # carries the trust store and it is genuinely empty: that is a total gap, a
        # guaranteed mTLS hard-stop during the 2026 rotation. We fall through and let
        # the missing-roots loop below report all required roots missing (CRITICAL).
        missing = []
        for r in required_roots:
            name = r.get("name") if isinstance(r, dict) else r
            sha1 = r.get("sha1") if isinstance(r, dict) else None
            if _norm(name) in present_norm:
                continue
            if sha1 and _norm(sha1) in present_norm:
                continue
            missing.append(r)
        # Only a trust store we can authoritatively read (introspectable) can be
        # declared "missing roots". A partial list leaked from a non-authoritative
        # source must not false-scream CRITICAL; report it out-of-band instead.
        if missing and not ctx.introspectable:
            res.add(Finding(
                check_id="C.CA.TRUST_STORE_UNAVAILABLE",
                title="Trust store only partially visible in this config source",
                severity=Severity.LOW,
                detail="Some required root CAs were not found, but this source does not "
                       "authoritatively enumerate the trust store, so absence here does "
                       "not prove they are missing. Verify the full trust store "
                       "out-of-band.",
                remediation="Confirm all 7 required root CAs are installed (see "
                            "docs/RULE_AUTHORITY.md).",
                locator=f"TlsContext '{ctx.name}'",
            ))
            missing = []
        if missing:
            def _label(r):
                if isinstance(r, dict):
                    return f"{r.get('name')} (SHA1 {r.get('sha1')})" if r.get("sha1") else r.get("name")
                return str(r)
            res.add(Finding(
                check_id="C.CA.ROOT_MISSING",
                title=f"{len(missing)} of {len(required_roots)} required root CAs missing",
                severity=Severity.CRITICAL,
                detail="Trust store is missing root CAs Microsoft anchors Teams SIP "
                       "certificates in (per the 2025-12 Direct Routing CA update). "
                       "Handshake hard-fails once rotation reaches an untrusted root. "
                       "Missing: " + "; ".join(_label(r) for r in missing),
                remediation="Install the missing root CA chains into the Teams TLS "
                            "context trust store before the next Microsoft rotation.",
                locator=f"TlsContext '{ctx.name}'",
            ))

        # --- FusionConnect-class media-trust note (honest scope) ---
        # In that incident, SIGNALING survived while Microsoft's media relays
        # presented rotated DigiCert certs and SRTP died -> one-way audio with a
        # clean portal. The relay side is Microsoft's and not config-catchable;
        # what IS true and checkable: when SRTP is on and this source cannot
        # prove the full 7-root store (separately-imported or incomplete), the
        # media stack's trust path is unverified too. INFO: a verify step,
        # never a failure claim about Microsoft's side.
        srtp_on = teams.srtp_enabled is True
        store_unproven = (not ctx.introspectable) or bool(missing)
        if srtp_on and store_unproven:
            res.add(Finding(
                check_id="C.SRTP.MEDIA_TRUST_UNVERIFIED",
                title="SRTP media trust path not verifiable from this source",
                severity=Severity.INFO,
                detail="Microsoft's media relays rotate certificates on the same "
                       "2026 root set; an SBC whose media stack lacks the new roots "
                       "gets one-way audio with healthy signaling (the FusionConnect "
                       "incident class). This source does not prove the full 7-root "
                       "store, and on some vendors the media stack uses a separate "
                       "trust store from SIP signaling.",
                remediation="Confirm all 7 required roots are installed in the trust "
                            "store the MEDIA/SRTP stack uses, not only the SIP TLS "
                            "context.",
                locator=f"iface '{teams.name}'",
            ))

        # --- Cisco IOS XE firmware floor for the EKU change (FN74345, Critical) ---
        # The permanent fix for the clientAuth-EKU deprecation is IOS XE 26.1.1
        # (segregates client/server certs); ISR-4000 hardware is EoL and cannot
        # run it. Fires only when the parser captured a version (tristate).
        if config.vendor == "cisco_cube":
            ver = config.raw_meta.get("ios_xe_version")
            floor = rules.get("iosxe_eku_fix_version", "26.1.1")
            if ver and _ver_lt(ver, floor):
                isr4k = "isr4" in str(config.raw_meta.get("platform_hint", "")).lower()
                res.add(Finding(
                    check_id="C.PLATFORM.IOSXE_EKU_FLOOR",
                    title=f"IOS XE {ver} predates the {floor} EKU fix"
                          + (" on EoL ISR-4000 hardware" if isr4k else ""),
                    severity=Severity.MEDIUM if isr4k else Severity.LOW,
                    detail="Cisco field notice FN74345 (Critical) tracks the public-CA "
                           f"clientAuth-EKU change; IOS XE {floor} is the permanent fix "
                           "(segregated client/server certificates). "
                           + ("ISR-4000 platforms are end-of-life and cannot run it, "
                              "forcing a hardware refresh." if isr4k else
                              "Plan the upgrade alongside the 2026 cert work."),
                    remediation=f"Upgrade to IOS XE {floor} or later"
                                + ("; ISR-4000 requires replacement hardware "
                                   "(Catalyst 8000)." if isr4k else "."),
                ))

        # --- leaf certificate checks (deep PKI, EKU, FQDN, expiry, chain) ---
        # Factored into cert_checks to keep this validator focused on the TLS
        # context and trust store.
        res.findings.extend(leaf_cert_findings(ctx, config, required_roots, warn_days))
        return res
