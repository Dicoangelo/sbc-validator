"""
Vendor-neutral normalized representation of an SBC configuration.

Every vendor parser (AudioCodes, Cisco CUBE, Ribbon, Oracle/Acme) emits one of
these. Validators only ever see the normalized form, never raw vendor syntax.
This is the contract that keeps validation logic vendor-agnostic.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class EKU(str, Enum):
    SERVER_AUTH = "serverAuth"
    CLIENT_AUTH = "clientAuth"


@dataclass
class Certificate:
    """A certificate referenced by the config (the SBC's own leaf, typically)."""
    subject_cn: Optional[str] = None
    sans: list[str] = field(default_factory=list)
    ekus: list[EKU] = field(default_factory=list)
    not_after: Optional[str] = None          # ISO date string, e.g. "2026-11-30"
    issuer_cn: Optional[str] = None
    chain_complete: bool = False             # full chain installed up to a root
    source_file: Optional[str] = None        # path, if a real PEM/DER was present


@dataclass
class TlsContext:
    """A TLS profile bound to a SIP interface."""
    name: str
    mtls_enabled: bool = False
    presented_cert: Optional[Certificate] = None
    # Identifiers of root CAs present in this context's trust store.
    # We carry identifiers (CN / fingerprint), never raw key material.
    trusted_root_ids: list[str] = field(default_factory=list)
    # False when the source (e.g. an AudioCodes .ini) references certs/roots that
    # are imported separately and are NOT present in this export. Lets validators
    # say "verify out-of-band" instead of false-claiming a missing cert/trust store.
    introspectable: bool = True


@dataclass
class SipInterface:
    name: str
    role: str = "unknown"        # "teams" | "carrier" | "internal" | "unknown"
    fqdn: Optional[str] = None
    tls_context: Optional[TlsContext] = None
    transport: Optional[str] = None          # "tls" | "tcp" | "udp"
    options_keepalive: bool = False          # SIP OPTIONS ping enabled
    normalization_profile: Optional[str] = None  # header/SIP manipulation set
    offered_codecs: list[str] = field(default_factory=list)  # e.g. ["PCMU","G722"]
    dtmf_method: Optional[str] = None        # "rfc2833" | "inband" | "info"
    srtp_enabled: bool = False               # media encryption (SDP a=crypto / SRTP)


@dataclass
class MediaRealm:
    name: str
    # Public/NAT-facing address advertised in SDP. None => likely a NAT problem.
    advertised_public_ip: Optional[str] = None
    local_ip: Optional[str] = None
    ice_enabled: bool = False
    symmetric_rtp: bool = False
    # Which leg this realm serves. An "internal"/LAN realm legitimately uses a
    # private address, so the public-advertisement checks (domain D) must not fire
    # on it. "teams"/"carrier"/"unknown" are treated as public-facing.
    role: str = "unknown"        # "teams" | "carrier" | "internal" | "unknown"


@dataclass
class AccessControlEntry:
    """One IP access-control rule on the SBC perimeter.

    plane:   "signaling" | "media" | "both"   (what the rule governs)
    ip_version: 4 | 6
    action:  "permit" | "deny"
    cidr:    e.g. "203.0.113.0/28"  (None for a catch-all default rule)
    """
    plane: str = "both"
    ip_version: int = 4
    action: str = "permit"
    cidr: Optional[str] = None


@dataclass
class NormalizedConfig:
    """The single object validators consume."""
    vendor: str
    sbc_fqdn: Optional[str] = None
    sip_interfaces: list[SipInterface] = field(default_factory=list)
    media_realms: list[MediaRealm] = field(default_factory=list)
    # SBC routing rules as (src_role, dst_role) pairs (e.g. ("teams","carrier")).
    # Empty => the source didn't carry routing info (don't assess routing).
    routes: list[tuple] = field(default_factory=list)
    # Whether incoming Teams traffic is classified to an IP Group. None = unknown
    # (source carried no classification info); validators stay silent on None.
    teams_classified: Optional[bool] = None
    # Perimeter access-control rules (domain S). Empty => source carried no ACL
    # info; the security validator stays silent rather than false-claiming exposure.
    access_controls: list[AccessControlEntry] = field(default_factory=list)
    # Whether the SBC validates that inbound RTP source matches the SDP-negotiated
    # peer (anti media-injection). None => unknown / not in this source.
    rtp_source_validation: Optional[bool] = None
    # Free-form, vendor-specific leftovers kept for explainability in findings.
    raw_meta: dict = field(default_factory=dict)

    def teams_interface(self) -> Optional[SipInterface]:
        for iface in self.sip_interfaces:
            if iface.role == "teams":
                return iface
        return None

    def carrier_interface(self) -> Optional[SipInterface]:
        for iface in self.sip_interfaces:
            if iface.role in ("carrier", "internal"):
                return iface
        return None
