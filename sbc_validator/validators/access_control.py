"""
Domain S - Security / Access-Control posture (the carrier-leg perimeter).

The research corpus (vendor hardening guides + the whitespace analysis) treats
the IP access-control posture as a first-class SBC failure surface, distinct
from the Teams-leg TLS wedge. The named failure modes:

  * Media-plane ACL omission: signaling IPs permitted but the carrier's RTP
    media subnet is not -> INVITE accepted, inbound RTP dropped -> one-way audio
    misdiagnosed as a codec/NAT fault.
  * Overly broad CIDR permit: a /16 where the carrier publishes a /28 -> the SIP
    parsing engine is exposed to hundreds of unauthorized hosts.
  * IPv6 plane neglect: a strict IPv4 default-deny with an empty IPv6 ACL leaves
    the SBC effectively default-allow over IPv6 (perimeter bypass).
  * Missing default-deny: relying on the system-default "admit any peer" rule
    leaves the SBC open to SIP scanning / REGISTER brute force / DDoS reflection.
  * RTP source-address validation disabled: rogue media accepted -> reflection DoS.

Like the routing validator, this fires ONLY when the source actually carries
access-control information (access_controls non-empty or rtp_source_validation
known). With nothing to assess it stays silent - absent vs. not-in-this-source.
Per-vendor ACL extraction (AudioCodes Firewall/IPACL, Oracle access-control,
Cisco/Ribbon ACLs) is what lights this up on real configs.
"""
from __future__ import annotations

import ipaddress

from ..models import NormalizedConfig
from .base import AbstractValidator, Finding, Severity, ValidatorResult

# A permit broader than this is suspicious for a carrier trunk (carriers publish
# tight /28-/32 ranges); flag /23 and wider (prefix length below this).
_BROAD_PREFIX_V4 = 24
_BROAD_PREFIX_V6 = 48


class AccessControlValidator(AbstractValidator):
    domain = "S"

    def validate(self, config: NormalizedConfig) -> ValidatorResult:
        res = ValidatorResult(domain=self.domain)
        acls = config.access_controls

        # Nothing to assess from this source -> stay silent.
        if not acls and config.rtp_source_validation is None:
            return res

        permits = [a for a in acls if a.action == "permit"]
        has_default_deny = any(a.action == "deny" and a.cidr in (None, "0.0.0.0/0", "::/0")
                               for a in acls)

        # Missing default-deny: system-default admits any peer.
        if permits and not has_default_deny:
            res.add(Finding(
                check_id="S.ACL.NO_DEFAULT_DENY",
                title="No default-deny rule on the SBC perimeter",
                severity=Severity.HIGH,
                detail="Permit rules exist but no catch-all deny. The system-default "
                       "'admit any peer' stays in effect, exposing the SIP engine to "
                       "scanning, REGISTER brute force, and DDoS reflection.",
                remediation="Add an explicit deny-all rule below the carrier allow-list.",
            ))

        # Overly broad permits.
        for a in permits:
            if not a.cidr:
                continue
            try:
                net = ipaddress.ip_network(a.cidr, strict=False)
            except ValueError:
                continue
            broad = _BROAD_PREFIX_V4 if net.version == 4 else _BROAD_PREFIX_V6
            if net.prefixlen < broad and not net.is_private:
                res.add(Finding(
                    check_id="S.ACL.BROAD_CIDR",
                    title=f"Overly broad permit {a.cidr}",
                    severity=Severity.MEDIUM,
                    detail=f"Permit {a.cidr} is wider than a carrier publishes; it admits "
                           "unauthorized hosts to the CPU-intensive SIP parser.",
                    remediation="Tighten the permit to the carrier's exact published range.",
                ))

        # Media-plane ACL omission: signaling permitted but media not.
        planes = {a.plane for a in permits}
        if ("signaling" in planes) and ("media" not in planes) and ("both" not in planes):
            res.add(Finding(
                check_id="S.ACL.MEDIA_PLANE_MISSING",
                title="Signaling permitted but no media-plane ACL",
                severity=Severity.HIGH,
                detail="The carrier's signaling IPs are allowed but its RTP media subnet "
                       "is not. INVITEs are accepted, inbound RTP is dropped -> one-way "
                       "audio commonly misdiagnosed as a codec/NAT problem.",
                remediation="Permit the carrier's media (RTP) subnet, for signaling and media.",
            ))

        # IPv6 plane neglect: IPv4 rules present, no IPv6 rules at all.
        versions = {a.ip_version for a in acls}
        if 4 in versions and 6 not in versions:
            res.add(Finding(
                check_id="S.ACL.IPV6_NEGLECT",
                title="IPv4 ACL present but IPv6 plane has no rules",
                severity=Severity.HIGH,
                detail="A strict IPv4 posture with an empty IPv6 ACL leaves the SBC "
                       "effectively default-allow over IPv6, bypassing the IPv4 perimeter.",
                remediation="Mirror the deny-all + carrier allow-list on the IPv6 plane.",
            ))

        # RTP source-address validation disabled.
        if config.rtp_source_validation is False:
            res.add(Finding(
                check_id="S.RTP.SOURCE_VALIDATION_OFF",
                title="RTP source-address validation disabled",
                severity=Severity.MEDIUM,
                detail="Inbound media is not checked against the SDP-negotiated peer, so "
                       "rogue RTP is accepted and processed -> reflection DoS / media injection.",
                remediation="Enable RTP source-address validation (latch to the SDP peer).",
            ))

        return res
