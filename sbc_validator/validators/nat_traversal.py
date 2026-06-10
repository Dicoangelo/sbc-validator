"""
Domain D — NAT Traversal validation (one-way audio prevention).

One-way audio is the top customer complaint and is overwhelmingly a NAT/media
path problem: the SBC advertises a private/local address in SDP, or lacks the
symmetric-RTP / ICE settings needed for remote workers behind NAT.
"""
from __future__ import annotations

import ipaddress

from ..models import NormalizedConfig
from .base import AbstractValidator, Finding, Severity, ValidatorResult


def _is_non_routable(ip: str) -> bool:
    """True if the address is NOT globally routable (private, loopback,
    link-local, or reserved/documentation) — all broken to advertise publicly."""
    try:
        return not ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


class NatTraversalValidator(AbstractValidator):
    domain = "D"

    def validate(self, config: NormalizedConfig) -> ValidatorResult:
        res = ValidatorResult(domain=self.domain)
        rules = self.ruleset.get("D", {})
        require_symmetric = rules.get("require_symmetric_rtp", True)

        if not config.media_realms:
            res.add(Finding(
                check_id="D.MEDIA.NO_REALM",
                title="No media realm found",
                severity=Severity.MEDIUM,
                detail="No media realm was normalized; NAT behavior can't be assessed.",
                remediation="Confirm the parser extracted media realm settings.",
            ))
            return res

        for realm in config.media_realms:
            loc = f"media realm '{realm.name}'"

            # The public-advertisement checks apply only to a realm facing the
            # public/Teams side. An "internal"/LAN realm legitimately advertises a
            # private address, so judging it as a NAT fault is a false BLOCK.
            if realm.role != "internal":
                if realm.advertised_public_ip is None:
                    # Missing advertised address is only a problem when there is no
                    # routable local address either; a realm bound to a public
                    # interface needs no separate NAT advertisement.
                    local_is_public = bool(realm.local_ip) and not _is_non_routable(realm.local_ip)
                    if not local_is_public:
                        res.add(Finding(
                            check_id="D.NAT.NO_PUBLIC_IP",
                            title="No public/NAT address advertised",
                            severity=Severity.HIGH,
                            detail="Realm advertises no external address; remote endpoints "
                                   "send media to an unreachable private address -> one-way audio.",
                            remediation="Configure the public NAT/SBC media address for SDP.",
                            locator=loc,
                        ))
                elif _is_non_routable(realm.advertised_public_ip):
                    res.add(Finding(
                        check_id="D.NAT.PRIVATE_ADVERTISED",
                        title="Non-routable IP advertised as public media address",
                        severity=Severity.CRITICAL,
                        detail=f"Realm advertises non-routable IP {realm.advertised_public_ip} "
                               "in SDP; remote-worker media will not return -> one-way audio.",
                        remediation="Set the advertised media address to a public, routable NAT IP.",
                        locator=loc,
                    ))

            if require_symmetric and realm.symmetric_rtp is False:
                res.add(Finding(
                    check_id="D.NAT.NO_SYMMETRIC_RTP",
                    title="Symmetric RTP disabled",
                    severity=Severity.MEDIUM,
                    detail="Without symmetric RTP/latching, media from NATed peers is "
                           "often dropped, producing one-way or no audio.",
                    remediation="Enable symmetric RTP (latching) on the media realm.",
                    locator=loc,
                ))

        # IPv6 mixed mode (authoritative: Microsoft supports IPv6 for Direct
        # Routing ONLY end-to-end without media bypass; "mixed mode SIP and media
        # (IPv6/IPv4)" is explicitly unsupported). The deterministic, config-visible
        # signal is public-facing media addresses in BOTH families. Tristate-safe:
        # fires only when the source genuinely carries both.
        def _fam(ip):
            try:
                return ipaddress.ip_address(ip).version
            except (ValueError, TypeError):
                return None
        fams = {}
        for realm in config.media_realms:
            if realm.role == "internal":
                continue
            v = _fam(realm.advertised_public_ip) or _fam(realm.local_ip)
            if v:
                fams.setdefault(v, realm.name)
        if 4 in fams and 6 in fams:
            res.add(Finding(
                check_id="D.IPV6.MIXED_MODE",
                title="Mixed IPv4/IPv6 media addressing on public-facing realms",
                severity=Severity.MEDIUM,
                detail="Microsoft Direct Routing supports IPv6 only end-to-end (and "
                       "only without media bypass); mixed IPv4/IPv6 SIP-and-media is "
                       f"explicitly unsupported. Realms '{fams[4]}' (v4) and "
                       f"'{fams[6]}' (v6) advertise different families -> calls can "
                       "blackhole when the negotiated family flips.",
                remediation="Run the Direct Routing path single-family end to end "
                            "(set IPAddressVersion accordingly on the trunk), or "
                            "separate the v6 estate onto its own trunk.",
            ))

        return res
