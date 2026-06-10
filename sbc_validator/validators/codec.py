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
        # Microsoft added AMR-WB to Direct Routing trunks in 2026 (prioritized when
        # offered). The shipped signed bundle predates it, so accept it here as a
        # ruleset-overridable code default (same pattern as the OPTIONS-interval
        # bounds) — a leg offering only AMR-WB must not false-fire NO_TEAMS_OVERLAP.
        amrwb = rules.get("teams_prioritized_wideband", "AMR-WB")
        teams_accepts = teams_supported | {amrwb}

        teams = config.teams_interface()
        # Tristate: offered_codecs is None when the source carries no codec info
        # (e.g. Perimeta adjacencies) -> judge nothing. [] = carried and empty.
        if teams is not None and teams_supported and teams.offered_codecs is not None:
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
            elif not (offered & teams_accepts):
                res.add(Finding(
                    check_id="E.CODEC.NO_TEAMS_OVERLAP",
                    title="No Teams-compatible codec offered",
                    severity=Severity.HIGH,
                    detail=f"Offered {sorted(offered)} shares nothing with Teams-supported "
                           f"{sorted(teams_supported)} -> 488 Not Acceptable.",
                    remediation="Add a Teams-supported codec (e.g. PCMU/PCMA/G722/SILK).",
                    locator=f"iface '{teams.name}'",
                ))

        # Cross-leg overlap (teams vs carrier): the B2BUA must bridge two codec
        # worlds. No overlap => the SBC must transcode (DSP cost) or there is no
        # audio; overlap only on a narrowband codec => a silent wideband downgrade.
        _WIDEBAND = {"G722", "G722.2", "AMR-WB", "SILK", "OPUS"}
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
                    detail="Legs share no codec, so the SBC must transcode in real time. "
                           "If transcoding/DSP capacity is not provisioned for the call "
                           "volume, calls drop or audio degrades (DSP exhaustion); if it "
                           "is unavailable, there is no audio at all.",
                    remediation="Align codec lists, or confirm transcoding is licensed and "
                                "DSP capacity is sized for peak concurrent calls.",
                ))
            else:
                offered_union = set().union(*(set(l.offered_codecs) for l in legs))
                if (offered_union & _WIDEBAND) and not (common & _WIDEBAND):
                    res.add(Finding(
                        check_id="E.CODEC.WIDEBAND_DOWNGRADE",
                        title="Cross-leg codec forces a narrowband downgrade",
                        severity=Severity.INFO,
                        detail="A leg offers a wideband codec but the only codec common to "
                               "both legs is narrowband, so calls connect at reduced audio "
                               "quality (or the SBC transcodes, adding DSP load).",
                        remediation="Add a shared wideband codec to both legs if HD audio "
                                    "is required end to end.",
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
        # Independent of the above: mixed methods are a distinct (worse) problem.
        # An `elif` here let a config that is BOTH non-preferred AND mixed escape the
        # MEDIUM inconsistency finding, scoring the worse config lower.
        if len(dtmf_methods) > 1:
            res.add(Finding(
                check_id="E.DTMF.INCONSISTENT",
                title="Inconsistent DTMF methods across legs",
                severity=Severity.MEDIUM,
                detail=f"Mixed DTMF methods {sorted(dtmf_methods)} across legs.",
                remediation="Use one DTMF method end to end (RFC 2833 preferred).",
            ))

        # In-band DTMF on the Teams leg specifically: the Microsoft media stack does
        # NOT support in-band DTMF (authoritative: Direct Routing protocols / RFC
        # standards page), so menu/IVR digits silently fail. This fires even when
        # another leg uses RFC 2833 (so the general METHOD check above stays quiet).
        # AMR-WB advisory (2026): Microsoft now offers AMR-WB on Direct Routing
        # non-bypass trunks (a=rtpmap:121 AMR-WB/16000) and PRIORITIZES it when the
        # SBC offers it back. Honest severity: calls FALL BACK to another common
        # codec when absent (Microsoft's own wording), so this is INFO, not a
        # failure claim. Fires only when the source carries a codec list.
        teams = config.teams_interface()
        if (teams is not None and teams.offered_codecs is not None
                and teams.offered_codecs and amrwb not in teams.offered_codecs):
            res.add(Finding(
                check_id="E.CODEC.AMRWB_NOT_OFFERED",
                title="Teams leg does not offer AMR-WB (2026 prioritized wideband)",
                severity=Severity.INFO,
                detail="Since 2026 Microsoft offers AMR-WB on Direct Routing trunks "
                       "and prioritizes it when the SBC offers it back. Without it, "
                       "calls negotiate another common codec (no outage), at reduced "
                       "audio quality. Also confirm the SBC tolerates the unknown "
                       "payload type 121 in Teams' SDP offer.",
                remediation="Add AMR-WB to the Teams-leg codec list if the SBC "
                            "supports it (HD audio); otherwise verify graceful "
                            "fallback against the 2026 Teams SDP offer.",
                locator=f"iface '{teams.name}'",
            ))

        if teams is not None and teams.dtmf_method == "inband":
            res.add(Finding(
                check_id="E.DTMF.INBAND_TEAMS",
                title="In-band DTMF on the Teams leg",
                severity=Severity.MEDIUM,
                detail="The Microsoft Teams media stack does not support in-band DTMF; "
                       "digits for IVRs, conference PINs, and menus will not register. "
                       "Direct Routing requires out-of-band DTMF (RFC 2833 telephone-event).",
                remediation="Set the Teams leg DTMF method to RFC 2833 (telephone-event).",
                locator=f"iface '{teams.name}'",
            ))

        return res
