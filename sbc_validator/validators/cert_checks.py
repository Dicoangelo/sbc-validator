"""Domain C leaf-certificate checks, factored out of ca_compliance.

Keeps the C validator focused on the TLS context and trust store, while the
denser leaf logic (deep PKI inspection, EKU, FQDN match, expiry, chain anchoring)
lives here. Pure: `leaf_cert_findings(...)` returns a list of Findings and never
touches I/O beyond the cert-file inspection it is given.
"""
from __future__ import annotations

from datetime import date, datetime, timezone

from ..models import EKU, NormalizedConfig
from .. import cert_inspect
from .base import Finding, Severity


def _name_covers(cert_name: str, fqdn: str) -> bool:
    """Does one cert name (CN or SAN) cover the FQDN? Wildcard-aware per RFC 2818:
    '*.a.com' matches 'foo.a.com' (exactly one label) but not 'bar.foo.a.com'
    and not 'a.com' itself. Microsoft Direct Routing supports these wildcards."""
    cert_name = (cert_name or "").strip().lower().rstrip(".")
    fqdn = (fqdn or "").strip().lower().rstrip(".")
    if not cert_name or not fqdn:
        return False
    if cert_name.startswith("*."):
        suffix = cert_name[2:]                       # the part after '*.'
        host, _, rest = fqdn.partition(".")
        return bool(host) and rest == suffix         # exactly one label replaces '*'
    return cert_name == fqdn


def _fqdn_matches(fqdn: str, names: list) -> bool:
    return any(_name_covers(n, fqdn) for n in names)


def leaf_cert_findings(ctx, config: NormalizedConfig,
                       required_roots: list, warn_days: int) -> list[Finding]:
    """All leaf-certificate findings for the Teams TLS context's presented cert.

    Mutates ctx.presented_cert to the deep-inspected cert when real PEM material is
    available (truth beats config-declared values). Returns findings in order.
    """
    out: list[Finding] = []
    cert = ctx.presented_cert

    # Deep pass: if real cert material is referenced, inspect it and let the actual
    # cert override the config-declared values (truth beats declaration).
    if cert is not None and cert.source_file:
        inspected = cert_inspect.inspect_file(cert.source_file)
        if inspected is not None:
            cert = inspected
            ctx.presented_cert = inspected
            out.append(Finding(
                check_id="C.CERT.DEEP_INSPECTED",
                title="Certificate inspected from file (not just config-declared)",
                severity=Severity.INFO,
                detail=f"EKU/SAN/expiry/chain read from {inspected.source_file}.",
                remediation="None (informational).",
                locator=f"cert CN={inspected.subject_cn}",
            ))
        elif not cert_inspect.available():
            out.append(Finding(
                check_id="C.CERT.DEEP_UNAVAILABLE",
                title="cryptography not installed; using config-declared cert values",
                severity=Severity.LOW,
                detail="Install 'cryptography' to inspect real cert material.",
                remediation="pip install cryptography",
            ))
    if cert is None:
        if not ctx.introspectable:
            # The source references a cert that's imported separately (e.g. an
            # AudioCodes .ini TLSContext). We can't inspect it here; don't claim it's
            # missing. Supplying the PEM enables the deep EKU/SAN/expiry/chain checks.
            out.append(Finding(
                check_id="C.CERT.UNAVAILABLE",
                title="SBC certificate not present in this config source",
                severity=Severity.LOW,
                detail="The Teams TLS context references a certificate that is "
                       "imported separately and isn't in this export, so EKU, SAN, "
                       "expiry, and chain cannot be inspected here.",
                remediation="Supply the leaf PEM (annotated leaf-cert) or verify the "
                            "serverAuth EKU, SAN=FQDN, and expiry out-of-band.",
                locator=f"TlsContext '{ctx.name}'",
            ))
            return out
        out.append(Finding(
            check_id="C.CERT.MISSING",
            title="No SBC certificate bound to Teams TLS context",
            severity=Severity.CRITICAL,
            detail="The SBC must present a leaf cert to Teams over mTLS.",
            remediation="Assign the SBC's leaf certificate to this TLS context.",
            locator=f"TlsContext '{ctx.name}'",
        ))
        return out

    # EKU: serverAuth required; clientAuth-only is deprecated
    if EKU.SERVER_AUTH not in cert.ekus:
        out.append(Finding(
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
            out.append(Finding(
                check_id="C.CERT.EKU_DUALUSE",
                title="SBC certificate is dual-use (server + client auth)",
                severity=Severity.LOW,
                detail="Dual-use TLS server certificates are deprecated; plan to "
                       "migrate to a serverAuth-only leaf before reissuance.",
                remediation="Request a serverAuth-only certificate at next renewal.",
                locator=f"cert CN={cert.subject_cn}",
            ))

    # FQDN match. Microsoft Direct Routing supports WILDCARD certs: a name like
    # *.adatum.biz matches sbc1.adatum.biz (one label only, per RFC 2818 and the MS
    # Direct Routing SIP spec). Exact-only matching here would false-flag the very
    # common wildcard Teams cert -> "re-issue" noise.
    names = ([cert.subject_cn] if cert.subject_cn else []) + cert.sans
    if config.sbc_fqdn and not _fqdn_matches(config.sbc_fqdn, names):
        out.append(Finding(
            check_id="C.CERT.FQDN_MISMATCH",
            title="Certificate CN/SAN does not match SBC FQDN",
            severity=Severity.HIGH,
            detail=f"SBC FQDN '{config.sbc_fqdn}' is not covered by cert names "
                   f"{names} (wildcards allowed). Teams matches the Contact-header "
                   "FQDN to the cert CN/SAN; a mismatch is rejected at TLS.",
            remediation="Re-issue the cert with the SBC FQDN (or a covering wildcard) "
                        "in the SAN list.",
            locator=f"cert CN={cert.subject_cn}",
        ))

    # Expiry
    if cert.not_after:
        try:
            exp = date.fromisoformat(cert.not_after)
            # not_after is a UTC date (cert_inspect uses not_valid_after_utc);
            # compare against UTC today, not the local date, to avoid an off-by-a-day
            # error in negative timezones near the boundary.
            days = (exp - datetime.now(timezone.utc).date()).days
            if days < 0:
                sev, msg = Severity.CRITICAL, f"expired {-days} days ago"
            elif days <= warn_days:
                sev, msg = Severity.MEDIUM, f"expires in {days} days"
            else:
                sev, msg = None, ""
            if sev is not None:
                out.append(Finding(
                    check_id="C.CERT.EXPIRY",
                    title=f"SBC certificate {msg}",
                    severity=sev,
                    detail=f"Leaf not_after={cert.not_after}.",
                    remediation="Renew the SBC certificate.",
                    locator=f"cert CN={cert.subject_cn}",
                ))
        except ValueError:
            pass

    # Declared-issuer program check (no PEM to verify): when the config declares
    # who issued the leaf and that CA is none of the named Direct Routing CAs
    # (MS Learn: "an approved CA such as DigiCert, GlobalSign, Sectigo, or
    # Entrust") or Microsoft itself, raise the verify-membership advisory. LOW:
    # we cannot prove non-membership, only that it needs checking (Gandi class).
    _PROGRAM_TOKENS = ("digicert", "globalsign", "sectigo", "entrust", "microsoft")
    if (cert.issuer_cn and not cert.source_file
            and not any(t in cert.issuer_cn.lower() for t in _PROGRAM_TOKENS)):
        out.append(Finding(
            check_id="C.CERT.ISSUER_PROGRAM_UNVERIFIED",
            title=f"Leaf issuer '{cert.issuer_cn}' is not a named Direct Routing CA",
            severity=Severity.LOW,
            detail="The declared issuer is not one of the CAs Microsoft names for "
                   "Direct Routing (DigiCert, GlobalSign, Sectigo, Entrust) or "
                   "Microsoft. A leaf from a CA outside the Microsoft Trusted Root "
                   "Program passes local validation and is then reset by Microsoft "
                   "at the handshake (the Gandi-wildcard incident class).",
            remediation="Verify this CA is in the Microsoft Trusted Root Program; "
                        "supply the leaf PEM for a full chain check.",
            locator=f"cert CN={cert.subject_cn}",
        ))

    # Trust-anchor chain validation: when a real PEM is referenced, verify the
    # chain's signatures and check it anchors to one of the required Microsoft roots.
    # Falls back to the config-declared chain_complete flag otherwise.
    chain = cert_inspect.verify_chain(cert.source_file) if cert.source_file else None
    if chain is not None:
        required_shas = {str(r.get("sha1", "")).upper().replace(":", "")
                         for r in required_roots if isinstance(r, dict)}
        loc = f"cert CN={cert.subject_cn}"
        if chain["leaf_self_signed"] and chain["length"] == 1:
            out.append(Finding(
                check_id="C.CERT.SELF_SIGNED",
                title="SBC certificate is self-signed",
                severity=Severity.HIGH,
                detail="Teams Direct Routing requires a certificate issued by a CA "
                       "in the Microsoft Trusted Root Program; a self-signed leaf "
                       "is rejected.",
                remediation="Obtain a CA-issued certificate whose chain anchors to a "
                            "required Microsoft/DigiCert root.",
                locator=loc))
        elif not chain["signatures_valid"]:
            out.append(Finding(
                check_id="C.CERT.CHAIN_INVALID",
                title="Certificate chain signature does not verify",
                severity=Severity.HIGH,
                detail="A certificate in the supplied chain is not validly signed by "
                       "its issuer; the chain is broken or tampered.",
                remediation="Re-export the correct leaf + intermediate chain.",
                locator=loc))
        elif not chain["reached_root"]:
            out.append(Finding(
                check_id="C.CERT.CHAIN_INCOMPLETE",
                title="Incomplete certificate chain (no root reached)",
                severity=Severity.MEDIUM,
                detail="Intermediate(s) are missing; the chain does not build to a "
                       "self-signed root.",
                remediation="Install the full intermediate chain on the SBC.",
                locator=loc))
        elif required_shas and chain["terminal_sha1"] not in required_shas:
            # Honest precision (the Gandi-wildcard class): the Microsoft Trusted
            # Root PROGRAM is much broader than the 7 service-side roots, so a
            # chain anchoring elsewhere is not provably bad — but it IS the exact
            # posture where a leaf passes local validation and Microsoft resets
            # the handshake if the CA is outside the program. Flag as a verify
            # step, not a verdict-driving HIGH.
            out.append(Finding(
                check_id="C.CERT.UNTRUSTED_ANCHOR",
                title="Chain anchors outside the Microsoft service roots — verify "
                      "program membership",
                severity=Severity.MEDIUM,
                detail=f"The chain terminates at root SHA-1 {chain['terminal_sha1']}, "
                       "not one of the 7 Microsoft/DigiCert service roots. That can be "
                       "fine (the Microsoft Trusted Root Program covers many CAs), but "
                       "a leaf from a CA OUTSIDE the program passes local validation "
                       "and is then reset by Microsoft at the handshake (the "
                       "Gandi-wildcard incident class).",
                remediation="Confirm this CA is in the Microsoft Trusted Root Program "
                            "before deploy; if uncertain, re-issue from DigiCert, "
                            "GlobalSign, Sectigo, or Entrust.",
                locator=loc))
        else:
            out.append(Finding(
                check_id="C.CERT.CHAIN_ANCHORED",
                title="Certificate chain anchors to a trusted root",
                severity=Severity.INFO,
                detail=f"Chain verified to root SHA-1 {chain['terminal_sha1']}.",
                remediation="None (informational).",
                locator=loc))
    elif cert.chain_complete is False:
        out.append(Finding(
            check_id="C.CERT.CHAIN_INCOMPLETE",
            title="Incomplete certificate chain",
            severity=Severity.MEDIUM,
            detail="Intermediate(s) appear missing; some peers fail to build a path.",
            remediation="Install the full intermediate chain on the SBC.",
            locator=f"cert CN={cert.subject_cn}",
        ))

    return out
