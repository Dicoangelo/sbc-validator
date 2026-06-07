"""
Domain C — TLS / SRTP & CA Compliance (primary wedge).

Encodes the Microsoft Direct Routing 2026 mTLS/CA requirements as logic driven
by a pulled rule bundle (so the authoritative root-CA list and counts live in
the signed ruleset, not hardcoded here). Requirements sourced from Microsoft
Learn and verified 2026-06-07 (see RULE_AUTHORITY.md):

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
from datetime import date

from ..models import EKU, NormalizedConfig
from .. import cert_inspect
from .base import AbstractValidator, Finding, Severity, ValidatorResult


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

        # --- mTLS enabled ---
        if not ctx.mtls_enabled:
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
        if not teams.srtp_enabled:
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

        # --- required root CAs present (count + identity) ---
        # The ruleset lists each required root as {"name", "sha1"} (authoritative,
        # sourced — see RULE_AUTHORITY.md). Older bundles may list plain name
        # strings; both are handled. Matching is naming-tolerant: configs name the
        # same root inconsistently ("DigiCert Global Root G2" vs "DigiCertGlobalRootG2"),
        # so we compare on a normalized form and also accept a SHA-1 thumbprint match.
        present_norm = {_norm(p) for p in ctx.trusted_root_ids}
        missing = []
        for r in required_roots:
            name = r.get("name") if isinstance(r, dict) else r
            sha1 = r.get("sha1") if isinstance(r, dict) else None
            if _norm(name) in present_norm:
                continue
            if sha1 and _norm(sha1) in present_norm:
                continue
            missing.append(r)
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

        # --- leaf certificate checks ---
        cert = ctx.presented_cert
        # Deep pass: if real cert material is referenced, inspect it and let the
        # actual cert override the config-declared values (truth beats declaration).
        if cert is not None and cert.source_file:
            inspected = cert_inspect.inspect_file(cert.source_file)
            if inspected is not None:
                cert = inspected
                ctx.presented_cert = inspected
                res.add(Finding(
                    check_id="C.CERT.DEEP_INSPECTED",
                    title="Certificate inspected from file (not just config-declared)",
                    severity=Severity.INFO,
                    detail=f"EKU/SAN/expiry/chain read from {inspected.source_file}.",
                    remediation="None (informational).",
                    locator=f"cert CN={inspected.subject_cn}",
                ))
            elif not cert_inspect.available():
                res.add(Finding(
                    check_id="C.CERT.DEEP_UNAVAILABLE",
                    title="cryptography not installed; using config-declared cert values",
                    severity=Severity.LOW,
                    detail="Install 'cryptography' to inspect real cert material.",
                    remediation="pip install cryptography",
                ))
        if cert is None:
            res.add(Finding(
                check_id="C.CERT.MISSING",
                title="No SBC certificate bound to Teams TLS context",
                severity=Severity.CRITICAL,
                detail="The SBC must present a leaf cert to Teams over mTLS.",
                remediation="Assign the SBC's leaf certificate to this TLS context.",
                locator=f"TlsContext '{ctx.name}'",
            ))
            return res

        # EKU: serverAuth required; clientAuth-only is deprecated
        if EKU.SERVER_AUTH not in cert.ekus:
            res.add(Finding(
                check_id="C.CERT.EKU_NO_SERVERAUTH",
                title="SBC certificate missing Server Authentication EKU",
                severity=Severity.HIGH,
                detail="Effective June 2026 the leaf must include serverAuth EKU; "
                       "dual-use/clientAuth-only certs are being deprecated by the "
                       "Chrome Root Program and will lose trust.",
                remediation="Re-issue the SBC cert with the Server Authentication EKU.",
                locator=f"cert CN={cert.subject_cn}",
            ))
        elif cert.ekus == [EKU.CLIENT_AUTH] or set(cert.ekus) == {EKU.SERVER_AUTH, EKU.CLIENT_AUTH}:
            # has serverAuth but also carries dual-use baggage
            if EKU.CLIENT_AUTH in cert.ekus:
                res.add(Finding(
                    check_id="C.CERT.EKU_DUALUSE",
                    title="SBC certificate is dual-use (server + client auth)",
                    severity=Severity.LOW,
                    detail="Dual-use TLS server certificates are deprecated; plan to "
                           "migrate to a serverAuth-only leaf before reissuance.",
                    remediation="Request a serverAuth-only certificate at next renewal.",
                    locator=f"cert CN={cert.subject_cn}",
                ))

        # FQDN match
        names = ([cert.subject_cn] if cert.subject_cn else []) + cert.sans
        if config.sbc_fqdn and config.sbc_fqdn not in names:
            res.add(Finding(
                check_id="C.CERT.FQDN_MISMATCH",
                title="Certificate CN/SAN does not match SBC FQDN",
                severity=Severity.HIGH,
                detail=f"SBC FQDN '{config.sbc_fqdn}' not found in cert names {names}.",
                remediation="Re-issue the cert with the SBC FQDN in the SAN list.",
                locator=f"cert CN={cert.subject_cn}",
            ))

        # Expiry
        if cert.not_after:
            try:
                exp = date.fromisoformat(cert.not_after)
                days = (exp - date.today()).days
                if days < 0:
                    sev, msg = Severity.CRITICAL, f"expired {-days} days ago"
                elif days <= warn_days:
                    sev, msg = Severity.MEDIUM, f"expires in {days} days"
                else:
                    sev, msg = None, ""
                if sev is not None:
                    res.add(Finding(
                        check_id="C.CERT.EXPIRY",
                        title=f"SBC certificate {msg}",
                        severity=sev,
                        detail=f"Leaf not_after={cert.not_after}.",
                        remediation="Renew the SBC certificate.",
                        locator=f"cert CN={cert.subject_cn}",
                    ))
            except ValueError:
                pass

        # Chain completeness
        if not cert.chain_complete:
            res.add(Finding(
                check_id="C.CERT.CHAIN_INCOMPLETE",
                title="Incomplete certificate chain",
                severity=Severity.MEDIUM,
                detail="Intermediate(s) appear missing; some peers fail to build a path.",
                remediation="Install the full intermediate chain on the SBC.",
                locator=f"cert CN={cert.subject_cn}",
            ))

        return res
