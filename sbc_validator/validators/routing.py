"""
Domain G - Routing & Classification.

Even a perfectly secured, codec-compatible SBC drops every call if incoming Teams
traffic isn't classified to an IP Group, or if there's no routing rule for a
direction. These are the "everything looks right but no calls connect / 404"
faults a vet checks early.

This validator only fires when the config source actually carries routing or
classification information (e.g. the AudioCodes IP2IPRouting + ClassifyByProxySet
tables). When the source has none (config.routes empty AND teams_classified is
None), it stays silent rather than false-claiming a routing gap - the same
"absent vs not-present-in-this-source" discipline as the TLS trust-store check.
"""
from __future__ import annotations

from ..models import NormalizedConfig
from .base import AbstractValidator, Finding, Severity, ValidatorResult


class RoutingValidator(AbstractValidator):
    domain = "G"

    def validate(self, config: NormalizedConfig) -> ValidatorResult:
        res = ValidatorResult(domain=self.domain)

        # Not introspectable from this source -> say nothing.
        if config.teams_classified is None and not config.routes:
            return res

        teams = config.teams_interface()
        if teams is None:
            return res

        # Classification: unclassified incoming Teams traffic is rejected.
        if config.teams_classified is False:
            res.add(Finding(
                check_id="G.CLASS.UNCLASSIFIED",
                title="Incoming Teams traffic is not classified to an IP Group",
                severity=Severity.HIGH,
                detail="No classification (ClassifyByProxySet or a Classification rule) "
                       "matches the Teams source, so the SBC cannot map inbound Teams "
                       "requests to the Teams IP Group and rejects them.",
                remediation="Classify the Teams leg (enable ClassifyByProxySet on the "
                            "Teams IP Group, or add a Classification rule for it).",
                locator=f"iface '{teams.name}'",
            ))

        # Routing: Direct Routing needs both directions.
        if config.routes:
            teams_to_other = any(s == "teams" and d != "teams" for s, d in config.routes)
            other_to_teams = any(d == "teams" and s != "teams" for s, d in config.routes)
            if not teams_to_other:
                res.add(Finding(
                    check_id="G.ROUTE.NO_FROM_TEAMS",
                    title="No routing rule for calls from Teams to the trunk",
                    severity=Severity.HIGH,
                    detail="There is no SBC routing rule with the Teams leg as source. "
                           "Outbound calls placed from Teams get no route (SIP 404).",
                    remediation="Add a routing rule: source = Teams IP Group, "
                                "destination = the carrier/SIP-trunk IP Group.",
                ))
            if not other_to_teams:
                res.add(Finding(
                    check_id="G.ROUTE.NO_TO_TEAMS",
                    title="No routing rule for calls to Teams from the trunk",
                    severity=Severity.HIGH,
                    detail="There is no SBC routing rule with the Teams leg as "
                           "destination. Inbound PSTN calls toward Teams get no route.",
                    remediation="Add a routing rule: source = carrier/SIP-trunk IP "
                                "Group, destination = Teams IP Group.",
                ))

        return res
