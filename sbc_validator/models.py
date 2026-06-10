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
    # Tristate: True = chain installed to a root, False = observed incomplete,
    # None = the source did not carry chain info (judge nothing).
    chain_complete: Optional[bool] = None
    source_file: Optional[str] = None        # path, if a real PEM/DER was present


@dataclass
class TlsContext:
    """A TLS profile bound to a SIP interface."""
    name: str
    # Tristate: None = the source did not carry an mTLS setting (judge nothing).
    mtls_enabled: Optional[bool] = None
    presented_cert: Optional[Certificate] = None
    # Identifiers of root CAs present in this context's trust store.
    # We carry identifiers (CN / fingerprint), never raw key material.
    trusted_root_ids: list[str] = field(default_factory=list)
    # False when the source (e.g. an AudioCodes .ini) references certs/roots that
    # are imported separately and are NOT present in this export. Lets validators
    # say "verify out-of-band" instead of false-claiming a missing cert/trust store.
    introspectable: bool = True
    # Minimum TLS protocol version this context will accept, e.g. "1.2".
    # Tristate: None = the source did not carry a version floor (judge nothing).
    min_tls_version: Optional[str] = None
    # SIP-TLS cipher suites this context offers, in IANA
    # ("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384") or OpenSSL
    # ("ECDHE-RSA-AES256-GCM-SHA384") form. Tristate: None = not carried by the
    # source (judge nothing); [] = carried but empty.
    cipher_suites: Optional[list[str]] = None


@dataclass
class SipInterface:
    name: str
    role: str = "unknown"        # "teams" | "carrier" | "internal" | "unknown"
    fqdn: Optional[str] = None
    tls_context: Optional[TlsContext] = None
    transport: Optional[str] = None          # "tls" | "tcp" | "udp"
    # Tristate (None = not carried by the source): SIP OPTIONS keep-alive enabled.
    options_keepalive: Optional[bool] = None
    # OPTIONS keep-alive interval in seconds. Microsoft requires 60-180s per trunk.
    # Tristate: None = the source did not carry an interval (judge nothing).
    options_keepalive_interval: Optional[int] = None
    # FQDN the SBC presents in the SIP Contact header. Direct Routing resolves the
    # tenant from this in carrier/multi-tenant hosting. None = not carried.
    contact_fqdn: Optional[str] = None
    normalization_profile: Optional[str] = None  # header/SIP manipulation set
    offered_codecs: list[str] = field(default_factory=list)  # e.g. ["PCMU","G722"]
    dtmf_method: Optional[str] = None        # "rfc2833" | "inband" | "info"
    # Tristate (None = not carried): media encryption (SDP a=crypto / SRTP).
    srtp_enabled: Optional[bool] = None


@dataclass
class MediaRealm:
    name: str
    # Public/NAT-facing address advertised in SDP. None => likely a NAT problem.
    advertised_public_ip: Optional[str] = None
    local_ip: Optional[str] = None
    ice_enabled: bool = False
    # Tristate (None = not carried by the source): symmetric RTP / latching.
    symmetric_rtp: Optional[bool] = None
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
