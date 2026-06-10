"""
Domain B — Cross-vendor SIP interoperability.

Checks the signaling-plane settings that most often break Teams Direct Routing
interop and cross-vendor bridging:
  * Teams SIP interface must use TLS transport (DR requires it).
  * SIP OPTIONS keep-alive should be enabled (Teams marks the SBC unhealthy
    without it -> intermittent routing failures).
  * A header/SIP normalization profile should exist when bridging a Teams leg to
    a carrier/other-vendor leg (proprietary headers, P-Asserted-Identity, etc.).
"""
from __future__ import annotations

import ipaddress

from ..models import NormalizedConfig
from .base import AbstractValidator, Finding, Severity, ValidatorResult


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(str(host).strip())
        return True
    except ValueError:
        return False


def _registrable(host: str) -> str:
    """Last two labels, a cheap registrable-domain proxy (good enough to tell
    'contoso.com' apart from 'adatum.biz'; not a public-suffix-list parser)."""
    parts = [p for p in host.split(".") if p]
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _same_registered_domain(a: str, b: str) -> bool:
    """True if a and b are the same host, one is a subdomain of the other, or they
    share a registrable base. Used to validate a carrier Contact FQDN sits under
    the SBC's registered domain (customer.sbc1.adatum.biz vs sbc1.adatum.biz)."""
    if a == b or a.endswith("." + b) or b.endswith("." + a):
        return True
    return _registrable(a) == _registrable(b)


class InteropValidator(AbstractValidator):
    domain = "B"

    def validate(self, config: NormalizedConfig) -> ValidatorResult:
        res = ValidatorResult(domain=self.domain)
        rules = self.ruleset.get("B", {})
        teams_required_transport = rules.get("teams_required_transport", "tls")

        # Teams refuses a Contact/OPTIONS whose hostname is an IP (403 Forbidden);
        # the identity must be the SBC FQDN that also matches the cert CN/SAN.
        # (Microsoft Direct Routing SIP spec.)
        if config.sbc_fqdn and _is_ip(config.sbc_fqdn):
            res.add(Finding(
                check_id="B.SIP.IDENTITY_IS_IP",
                title="SBC identity is an IP address, not an FQDN",
                severity=Severity.HIGH,
                detail="Direct Routing rejects an INVITE/OPTIONS whose Contact host is an "
                       "IP with 403 Forbidden. The Contact must carry the SBC FQDN, which "
                       "must also match the certificate CN/SAN.",
                remediation="Present the SBC FQDN (not an IP) as the Teams-facing identity.",
            ))

        teams = config.teams_interface()
        if teams is None:
            res.add(Finding(
                check_id="B.IFACE.NO_TEAMS",
                title="No Teams-facing SIP interface identified",
                severity=Severity.MEDIUM,
                detail="Interop checks for the Teams leg cannot run.",
                remediation="Tag the Teams SIP interface (role='teams').",
            ))
            return res

        if (teams.transport or "").lower() != teams_required_transport:
            res.add(Finding(
                check_id="B.SIP.TRANSPORT",
                title=f"Teams interface transport is '{teams.transport}', not TLS",
                severity=Severity.HIGH,
                detail="Direct Routing requires TLS for SIP signaling; TCP/UDP will "
                       "be rejected by Teams.",
                remediation="Set the Teams SIP interface transport to TLS.",
                locator=f"iface '{teams.name}'",
            ))

        if teams.options_keepalive is False:
            res.add(Finding(
                check_id="B.SIP.OPTIONS_KEEPALIVE",
                title="SIP OPTIONS keep-alive not enabled on Teams interface",
                severity=Severity.MEDIUM,
                detail="Teams uses OPTIONS pings to track SBC health; without it the "
                       "SBC can be marked down, causing intermittent call failures.",
                remediation="Enable SIP OPTIONS keep-alive toward Teams.",
                locator=f"iface '{teams.name}'",
            ))

        # OPTIONS interval must sit in Microsoft's 60-180s window (authoritative:
        # "Connect the SBC" — pings MUST NOT be more often than every 60s nor less
        # often than every 180s per trunk). Bounds are ruleset-overridable; the
        # defaults are the MS-published values. Tristate-safe (silent if no interval).
        lo = rules.get("options_interval_min_s", 60)
        hi = rules.get("options_interval_max_s", 180)
        iv = teams.options_keepalive_interval
        if iv is not None and (iv < lo or iv > hi):
            res.add(Finding(
                check_id="B.SIP.OPTIONS_INTERVAL",
                title=f"SIP OPTIONS interval {iv}s is outside Microsoft's {lo}-{hi}s window",
                severity=Severity.MEDIUM,
                detail="Direct Routing requires SBC OPTIONS pings no more often than "
                       f"every {lo}s and no less often than every {hi}s per trunk. Outside "
                       "this window the SBC can be rate-limited or marked unhealthy, "
                       "causing intermittent routing failures.",
                remediation=f"Set the Teams OPTIONS keep-alive interval between {lo} and {hi} seconds.",
                locator=f"iface '{teams.name}'",
            ))

        # Contact-header FQDN: Direct Routing resolves the tenant from the Contact
        # host (not the phone number), so in carrier/multi-tenant hosting each
        # customer subdomain must sit under the SBC's registered domain. A Contact
        # FQDN outside that domain lands on the wrong tenant or none. Tristate-safe.
        cf = (teams.contact_fqdn or "").strip().lower().rstrip(".")
        sf = (config.sbc_fqdn or "").strip().lower().rstrip(".")
        if cf and sf and not _same_registered_domain(cf, sf):
            res.add(Finding(
                check_id="B.SIP.CONTACT_FQDN",
                title=f"Contact header FQDN '{cf}' is not under the SBC domain '{sf}'",
                severity=Severity.HIGH,
                detail="Direct Routing uses the Contact header FQDN to find the tenant. "
                       "In carrier/multi-tenant hosting each customer subdomain "
                       "(customer.sbc.carrier.com) must match the trunk and the wildcard "
                       "cert; a Contact FQDN outside the registered domain fails the lookup.",
                remediation="Present the customer's subdomain FQDN (under the SBC's "
                            "registered domain) in the Contact header for each tenant.",
                locator=f"iface '{teams.name}'",
            ))

        # The B2BUA has two legs: the carrier/trunk leg also needs OPTIONS
        # keep-alive so the SBC detects a dead trunk and busies it out, instead of
        # routing calls into a black hole. Advisory (some ITSPs don't answer OPTIONS).
        carrier = config.carrier_interface()
        if carrier is not None and carrier.options_keepalive is False:
            res.add(Finding(
                check_id="B.SIP.CARRIER_NO_KEEPALIVE",
                title="SIP OPTIONS keep-alive not enabled on the carrier leg",
                severity=Severity.INFO,
                detail="Without OPTIONS keep-alive toward the carrier/trunk, the SBC "
                       "cannot tell when the trunk goes dead; calls are routed to a "
                       "black hole instead of failing over.",
                remediation="Enable SIP OPTIONS keep-alive toward the carrier if the "
                            "ITSP supports it.",
                locator=f"iface '{carrier.name}'",
            ))

        # Bridging two legs of different roles without normalization is risky.
        roles = {i.role for i in config.sip_interfaces}
        bridging = "teams" in roles and ("carrier" in roles or "internal" in roles)
        if bridging and not any(i.normalization_profile for i in config.sip_interfaces):
            res.add(Finding(
                check_id="B.SIP.NO_NORMALIZATION",
                title="No SIP normalization profile while bridging vendors",
                severity=Severity.MEDIUM,
                detail="Bridging a Teams leg to a carrier/other-vendor leg without "
                       "header normalization commonly breaks caller ID, diversion, "
                       "and proprietary-header handling.",
                remediation="Apply a SIP message-manipulation/normalization profile.",
            ))

        return res
