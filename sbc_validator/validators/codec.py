"""
Domain E — Codec / media compatibility.

  * The Teams leg must offer at least one codec Teams supports, or every call
    fails codec negotiation (488 Not Acceptable Here).
  * When two legs bridge, they need a common codec or the SBC must transcode;
    no overlap + no transcode = no audio.
  * DTMF method should be RFC 2833 (telephone-event); inband/SIP-INFO mismatches
    are a classic cause of broken IVR / menu navigation.
"""
from __future__ import annotations

from ..models import NormalizedConfig
from .base import AbstractValidator, Finding, Severity, ValidatorResult


class CodecValidator(AbstractValidator):
    domain = "E"

    def validate(self, config: NormalizedConfig) -> ValidatorResult:
        res = ValidatorResult(domain=self.domain)
        rules = self.ruleset.get("E", {})
        teams_supported = set(rules.get("teams_supported_codecs", []))
        preferred_dtmf = rules.get("preferred_dtmf", "rfc2833")

        teams = config.teams_interface()
        if teams is not None and teams_supported:
            offered = set(teams.offered_codecs)
            if not offered:
                res.add(Finding(
                    check_id="E.CODEC.NONE_OFFERED",
                    title="Teams interface offers no codecs",
                    severity=Severity.HIGH,
                    detail="No codec list parsed for the Teams leg; negotiation will fail.",
                    remediation="Configure a codec list including a Teams-supported codec.",
                    locator=f"iface '{teams.name}'",
                ))
            elif not (offered & teams_supported):
                res.add(Finding(
                    check_id="E.CODEC.NO_TEAMS_OVERLAP",
                    title="No Teams-compatible codec offered",
                    severity=Severity.HIGH,
                    detail=f"Offered {sorted(offered)} shares nothing with Teams-supported "
                           f"{sorted(teams_supported)} -> 488 Not Acceptable.",
                    remediation="Add a Teams-supported codec (e.g. PCMU/PCMA/G722/SILK).",
                    locator=f"iface '{teams.name}'",
                ))

        # Cross-leg overlap (teams vs carrier) — transcode check is future work.
        legs = [i for i in config.sip_interfaces if i.offered_codecs]
        if len(legs) >= 2:
            common = set(legs[0].offered_codecs)
            for leg in legs[1:]:
                common &= set(leg.offered_codecs)
            if not common:
                res.add(Finding(
                    check_id="E.CODEC.NO_CROSS_OVERLAP",
                    title="No common codec across SIP legs",
                    severity=Severity.MEDIUM,
                    detail="Legs share no codec; without transcoding this yields no audio.",
                    remediation="Align codec lists or enable transcoding on the SBC.",
                ))

        # DTMF consistency
        dtmf_methods = {i.dtmf_method for i in config.sip_interfaces if i.dtmf_method}
        if dtmf_methods and preferred_dtmf not in dtmf_methods:
            res.add(Finding(
                check_id="E.DTMF.METHOD",
                title=f"DTMF method not {preferred_dtmf}",
                severity=Severity.LOW,
                detail=f"Configured DTMF {sorted(dtmf_methods)}; mismatches break IVR menus.",
                remediation=f"Standardize on {preferred_dtmf} (telephone-event).",
            ))
        elif len(dtmf_methods) > 1:
            res.add(Finding(
                check_id="E.DTMF.INCONSISTENT",
                title="Inconsistent DTMF methods across legs",
                severity=Severity.MEDIUM,
                detail=f"Mixed DTMF methods {sorted(dtmf_methods)} across legs.",
                remediation="Use one DTMF method end to end (RFC 2833 preferred).",
            ))

        return res
