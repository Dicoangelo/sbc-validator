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

from ..models import NormalizedConfig
from .base import AbstractValidator, Finding, Severity, ValidatorResult


class InteropValidator(AbstractValidator):
    domain = "B"

    def validate(self, config: NormalizedConfig) -> ValidatorResult:
        res = ValidatorResult(domain=self.domain)
        rules = self.ruleset.get("B", {})
        teams_required_transport = rules.get("teams_required_transport", "tls")

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

        if not teams.options_keepalive:
            res.add(Finding(
                check_id="B.SIP.OPTIONS_KEEPALIVE",
                title="SIP OPTIONS keep-alive not enabled on Teams interface",
                severity=Severity.MEDIUM,
                detail="Teams uses OPTIONS pings to track SBC health; without it the "
                       "SBC can be marked down, causing intermittent call failures.",
                remediation="Enable SIP OPTIONS keep-alive toward Teams.",
                locator=f"iface '{teams.name}'",
            ))

        # The B2BUA has two legs: the carrier/trunk leg also needs OPTIONS
        # keep-alive so the SBC detects a dead trunk and busies it out, instead of
        # routing calls into a black hole. Advisory (some ITSPs don't answer OPTIONS).
        carrier = config.carrier_interface()
        if carrier is not None and not carrier.options_keepalive:
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
