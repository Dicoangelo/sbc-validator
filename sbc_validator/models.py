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


@dataclass
class MediaRealm:
    name: str
    # Public/NAT-facing address advertised in SDP. None => likely a NAT problem.
    advertised_public_ip: Optional[str] = None
    local_ip: Optional[str] = None
    ice_enabled: bool = False
    symmetric_rtp: bool = False


@dataclass
class NormalizedConfig:
    """The single object validators consume."""
    vendor: str
    sbc_fqdn: Optional[str] = None
    sip_interfaces: list[SipInterface] = field(default_factory=list)
    media_realms: list[MediaRealm] = field(default_factory=list)
    # Free-form, vendor-specific leftovers kept for explainability in findings.
    raw_meta: dict = field(default_factory=dict)

    def teams_interface(self) -> Optional[SipInterface]:
        for iface in self.sip_interfaces:
            if iface.role == "teams":
                return iface
        return None
