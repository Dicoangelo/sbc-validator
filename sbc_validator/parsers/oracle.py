"""
Oracle Communications SBC (Acme Packet) parser - the fourth vendor.

Oracle's ACLI `show running-config` is a sequence of element blocks, each a
keyword header followed by indented `key value` attribute lines (with nested
sub-elements like `sip-port` inside `sip-interface`). Direct Routing is expressed
across realms, sip-interfaces, session-agents, tls-profiles, and media-security
policies. As with AudioCodes, the leaf certificate and trust-store roots are
imported separately, so the mapped TLS context is introspectable=False and domain
C reports "verify out-of-band" rather than false-claiming a missing cert/trust.

Honest scope: enough of the ACLI to resolve the Teams leg (transport, SRTP,
codecs, keep-alive, TLS profile) on one normalized model, proving the validators
are vendor-agnostic at N=4. Routing (local-policy) and FQDN are best-effort.
"""
from __future__ import annotations

import re

from ..models import (
    Certificate, NormalizedConfig, SipInterface, TlsContext,
)
from .base import AbstractParser

_ELEMENTS = {
    "sip-interface", "session-agent", "realm-config", "tls-profile",
    "media-sec-policy", "sdes-profile", "media-profile", "local-policy",
    "system-config", "sip-config", "sip-manipulation",
}
_CODER = {
    "pcmu": "PCMU", "pcma": "PCMA", "g711": "PCMU", "g722": "G722",
    "g729": "G729", "silk": "SILK", "opus": "OPUS",
}


def _blocks(text: str):
    """Yield (element_type, attrs: dict) for each ACLI element block.

    Attributes are flattened (nested sub-element keys are kept in the same dict),
    which is enough for the fields the mapper needs.
    """
    cur_type, attrs = None, {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        first = line.split()[0]
        if first in _ELEMENTS and (len(line.split()) == 1 or first in ("local-policy",)):
            if cur_type is not None:
                yield cur_type, attrs
            cur_type, attrs = first, {}
            continue
        if cur_type is not None:
            parts = line.split(None, 1)
            key = parts[0]
            val = parts[1].strip() if len(parts) > 1 else ""
            attrs.setdefault(key, val)     # first occurrence wins (header-level)
    if cur_type is not None:
        yield cur_type, attrs


class OracleAcmeParser(AbstractParser):
    vendor = "oracle_acme"

    @classmethod
    def sniff(cls, text: str) -> bool:
        return ("session-agent" in text and "realm-config" in text) or \
               ("sip-interface" in text and "realm-id" in text)

    def parse(self, text: str) -> NormalizedConfig:
        cfg = NormalizedConfig(vendor=self.vendor)
        cfg.raw_meta["parser"] = "oracle_acme/acli"

        leaf_cert_file = None
        m = re.search(r"#\s*sbc-validator:\s*leaf-cert\s+(\S+)", text)
        if m:
            leaf_cert_file = m.group(1)

        sip_ifaces, session_agents, realms = [], [], []
        media_profiles, media_sec = [], False
        tls_profiles: dict[str, dict] = {}
        hostname = None
        for etype, a in _blocks(text):
            if etype == "sip-interface":
                sip_ifaces.append(a)
            elif etype == "session-agent":
                session_agents.append(a)
            elif etype == "realm-config":
                realms.append(a)
            elif etype == "tls-profile" and a.get("name"):
                tls_profiles[a["name"]] = a
            elif etype == "media-profile" and a.get("name"):
                media_profiles.append(a["name"])
            elif etype in ("media-sec-policy", "sdes-profile"):
                media_sec = True
            elif etype == "system-config":
                hostname = a.get("hostname") or hostname

        cfg.sbc_fqdn = hostname

        # transport/tls per realm (from its sip-interface)
        iface_by_realm = {}
        for si in sip_ifaces:
            rid = si.get("realm-id")
            if rid:
                iface_by_realm[rid] = si

        # realm -> whether it references a media-security policy (=> SRTP)
        realm_srtp = {r.get("identifier"): bool(r.get("media-sec-policy"))
                      for r in realms if r.get("identifier")}

        codecs = []
        for mp in media_profiles:
            norm = _CODER.get(mp.lower().replace(".", "").replace("-", ""))
            if norm and norm not in codecs:
                codecs.append(norm)

        for sa in session_agents:
            host = (sa.get("hostname") or "").lower()
            rid = sa.get("realm-id") or ""
            role = "teams" if "pstnhub.microsoft.com" in host else "carrier"
            si = iface_by_realm.get(rid, {})
            tp = (si.get("transport-protocol") or sa.get("transport-method") or "").lower()
            transport = "tls" if "tls" in tp else ("tcp" if "tcp" in tp else
                                                   ("udp" if "udp" in tp else None))
            tls_name = si.get("tls-profile")
            ctx = None
            if transport == "tls":
                prof = tls_profiles.get(str(tls_name or ""), {})
                # Oracle tls-version: tlsv1/11/12/13 -> dotted; "compatibility"/auto
                # -> None (it negotiates up, so judge nothing). cipher-list -> suites.
                _VMAP = {"tlsv1": "1.0", "tlsv11": "1.1", "tlsv12": "1.2", "tlsv13": "1.3"}
                minv = _VMAP.get((prof.get("tls-version") or "").strip().lower())
                clist = prof.get("cipher-list")
                ciphers = ([c for c in re.split(r"[\s,:]+", clist) if c]
                           if clist else None)
                ctx = TlsContext(
                    name=str(tls_name or f"{rid}-tls"),
                    mtls_enabled=True,
                    presented_cert=(Certificate(source_file=leaf_cert_file)
                                    if leaf_cert_file else None),
                    trusted_root_ids=[],
                    introspectable=False,
                    min_tls_version=minv,
                    cipher_suites=ciphers,
                )
            ping = sa.get("ping-method") or si.get("options")
            try:
                ping_iv = int(sa["ping-interval"]) if sa.get("ping-interval") else None
            except (ValueError, TypeError):
                ping_iv = None
            cfg.sip_interfaces.append(SipInterface(
                name=str(rid or host or "sa"),
                role=role,
                fqdn=cfg.sbc_fqdn if role == "teams" else None,
                tls_context=ctx,
                transport=transport,
                options_keepalive=bool(ping and "options" in str(ping).lower()),
                options_keepalive_interval=ping_iv,
                offered_codecs=list(codecs),
                srtp_enabled=media_sec and realm_srtp.get(rid, False),
            ))
        return cfg
