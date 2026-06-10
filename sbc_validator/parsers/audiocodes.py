"""
Vendor parser dispatch.

Four vendors are implemented end-to-end on one normalized model: AudioCodes
(both the simplified INI projection and the real Mediant parameter-table .ini),
Cisco CUBE (IOS-XE running-config), Ribbon SBC Core (set-config), and Oracle
Acme Packet (ACLI). detect_and_parse sniffs the format and dispatches; the same
A-G + S validators run unmodified across all four.

Production note: real exports have richer grammar than the smoke-test samples
(AudioCodes indexed tables, Cisco voice-class tenants, etc.). The model held as
each vendor was added end-to-end rather than building four shallow parsers at once.
"""
from __future__ import annotations

import configparser

from ..models import (
    EKU, Certificate, MediaRealm, NormalizedConfig, SipInterface, TlsContext,
)
from .base import AbstractParser
from .audiocodes_ini import is_table_ini, map_to_config  # real .ini table format
from .cisco_cube import CiscoCubeParser  # real second-vendor parser (re-exported)
from .ribbon import RibbonParser         # real third-vendor parser (re-exported)
from .oracle import OracleAcmeParser     # real fourth-vendor parser (re-exported)


def _ekus(raw: str) -> list[EKU]:
    out = []
    for tok in (raw or "").split(","):
        tok = tok.strip()
        if tok == "serverAuth":
            out.append(EKU.SERVER_AUTH)
        elif tok == "clientAuth":
            out.append(EKU.CLIENT_AUTH)
    return out


class AudioCodesParser(AbstractParser):
    vendor = "audiocodes"

    @classmethod
    def sniff(cls, text: str) -> bool:
        head = text[:4000]
        low = head.lower()
        if "[audiocodes]" in low or "vendor = audiocodes" in low:
            return True
        # real AudioCodes .ini: parameter tables + AudioCodes-specific globals
        return is_table_ini(text) or "SBCMediaSecurityBehaviour" in head \
            or "EnableMediaSecurity" in head

    def parse(self, text: str) -> NormalizedConfig:
        # Real AudioCodes export = parameter-table .ini; dispatch to that mapper.
        if is_table_ini(text):
            return map_to_config(text)

        cp = configparser.ConfigParser()
        cp.read_string(text)

        cfg = NormalizedConfig(vendor=self.vendor)
        if cp.has_section("audiocodes"):
            cfg.sbc_fqdn = cp.get("audiocodes", "sbc_fqdn", fallback=None)

        # TLS contexts: sections like [tls:Teams]
        tls_contexts: dict[str, TlsContext] = {}
        for sect in cp.sections():
            if not sect.startswith("tls:"):
                continue
            name = sect.split(":", 1)[1]
            cert = None
            if cp.has_option(sect, "cert_cn") or cp.has_option(sect, "cert_file"):
                cert = Certificate(
                    subject_cn=cp.get(sect, "cert_cn", fallback=None),
                    sans=[s.strip() for s in cp.get(sect, "cert_sans", fallback="").split(",") if s.strip()],
                    ekus=_ekus(cp.get(sect, "cert_ekus", fallback="")),
                    not_after=cp.get(sect, "cert_not_after", fallback=None),
                    issuer_cn=cp.get(sect, "cert_issuer", fallback=None),
                    chain_complete=cp.getboolean(sect, "chain_complete", fallback=False),
                    source_file=cp.get(sect, "cert_file", fallback=None),
                )
            ciphers = cp.get(sect, "ciphers", fallback=None)
            tls_contexts[name] = TlsContext(
                name=name,
                mtls_enabled=cp.getboolean(sect, "mtls", fallback=False),
                presented_cert=cert,
                trusted_root_ids=[r.strip() for r in cp.get(sect, "trusted_roots", fallback="").split(",") if r.strip()],
                # Tristate: None when the source omits the field (judge nothing).
                min_tls_version=cp.get(sect, "min_tls", fallback=None) or None,
                cipher_suites=([c.strip() for c in ciphers.split(",") if c.strip()]
                               if ciphers is not None else None),
            )

        # SIP interfaces: sections like [sip:Teams-SIP]
        for sect in cp.sections():
            if not sect.startswith("sip:"):
                continue
            name = sect.split(":", 1)[1]
            ctx_name = cp.get(sect, "tls_context", fallback=None)
            cfg.sip_interfaces.append(SipInterface(
                name=name,
                role=cp.get(sect, "role", fallback="unknown"),
                fqdn=cp.get(sect, "fqdn", fallback=None),
                tls_context=tls_contexts.get(ctx_name) if ctx_name else None,
                transport=cp.get(sect, "transport", fallback=None),
                options_keepalive=cp.getboolean(sect, "options_keepalive", fallback=False),
                normalization_profile=cp.get(sect, "normalization_profile", fallback=None) or None,
                offered_codecs=[c.strip() for c in cp.get(sect, "codecs", fallback="").split(",") if c.strip()],
                dtmf_method=cp.get(sect, "dtmf_method", fallback=None) or None,
                srtp_enabled=cp.getboolean(sect, "srtp", fallback=False),
            ))

        # Media realms: sections like [media:Default]
        for sect in cp.sections():
            if not sect.startswith("media:"):
                continue
            name = sect.split(":", 1)[1]
            cfg.media_realms.append(MediaRealm(
                name=name,
                advertised_public_ip=cp.get(sect, "advertised_public_ip", fallback=None) or None,
                local_ip=cp.get(sect, "local_ip", fallback=None) or None,
                ice_enabled=cp.getboolean(sect, "ice", fallback=False),
                symmetric_rtp=cp.getboolean(sect, "symmetric_rtp", fallback=False),
            ))

        return cfg


ALL_PARSERS = [AudioCodesParser, CiscoCubeParser, RibbonParser, OracleAcmeParser]


def detect_and_parse(text: str) -> NormalizedConfig:
    for pcls in ALL_PARSERS:
        if pcls.sniff(text):
            return pcls().parse(text)
    raise ValueError("No vendor parser matched the supplied config export.")
