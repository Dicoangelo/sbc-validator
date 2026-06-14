"""
Ribbon SBC Core parser — the third vendor.

Ribbon's `show configuration` is a flat list of `set <path...> <value>` lines,
which is easier to read than Cisco's nested blocks but expresses the same facts.
This parser walks those set-paths and emits the same NormalizedConfig the
AudioCodes and Cisco parsers do, so the A-E validators run unchanged. Three
vendors on one model is the real test that the normalization holds.

Constructs read:
  * set system fqdn <fqdn>
  * set system security pki certificate <RootName> type remote   -> trusted roots
  * set profiles security tlsProfile <P> clientCertName / authClient
  * set addressContext default zone <ZONE> ...                   -> SIP interfaces
      transportProtocolsAllowed sip-tls|sip-tcp|sip-udp
      sipTrunkGroup <TG> signaling messageManipulation outputAdapterProfile <N>
      sipTrunkGroup <TG> signaling sipOptions enabled            -> keepalive
      sipTrunkGroup <TG> media ... codec <CODEC>                 -> offered codecs
      sipTrunkGroup <TG> media dtmf <method>
  * set addressContext default media mediaAddress <ip> symmetricRtp enabled

Scope is the Direct Routing path; widen from real customer exports.
"""
from __future__ import annotations

import re

from ..models import (
    Certificate, MediaRealm, NormalizedConfig, SipInterface, TlsContext,
)
from .base import AbstractParser

_RIBBON_CODEC = {
    "PCMU": "PCMU", "PCMA": "PCMA", "G722": "G722", "G729": "G729",
    "g711u": "PCMU", "g711a": "PCMA", "g722": "G722", "g729": "G729",
}
_ROLE_BY_NAME = {"teams": "teams", "carrier": "carrier", "pstn": "carrier",
                 "itsp": "carrier", "internal": "internal"}


def _role_for_zone(zone: str) -> str:
    z = zone.lower()
    for key, role in _ROLE_BY_NAME.items():
        if key in z:
            return role
    return "unknown"


class RibbonParser(AbstractParser):
    vendor = "ribbon"

    @classmethod
    def sniff(cls, text: str) -> bool:
        return "set addressContext" in text or "set system security pki" in text \
            or "set profiles security tlsProfile" in text

    def parse(self, text: str) -> NormalizedConfig:
        cfg = NormalizedConfig(vendor=self.vendor)

        fqdn = None
        roots: list[str] = []
        tls_profiles: dict[str, dict] = {}
        zones: dict[str, dict] = {}
        media_ip = None
        symmetric = True
        leaf_cert_file = None

        m = re.search(r"#\s*sbc-validator:\s*leaf-cert\s+(\S+)", text)
        if m:
            leaf_cert_file = m.group(1)

        for raw in text.splitlines():
            line = raw.strip()
            if not line.startswith("set "):
                continue
            toks = line.split()

            if toks[1:3] == ["system", "fqdn"] and len(toks) >= 4:
                fqdn = toks[3]

            elif toks[1:5] == ["system", "security", "pki", "certificate"] and len(toks) >= 6:
                roots.append(toks[5])

            elif toks[1:4] == ["profiles", "security", "tlsProfile"] and len(toks) >= 6:
                pname = toks[4]
                p = tls_profiles.setdefault(pname, {"cert": None, "mtls": False,
                                                    "versions": [], "ciphers": []})
                if "clientCertName" in toks:
                    p["cert"] = toks[toks.index("clientCertName") + 1]
                if "authClient" in toks:
                    p["mtls"] = toks[toks.index("authClient") + 1].lower() == "true"
                # `v1_0 | v1_1 | v1_2 | v1_3  enable` -> that protocol is permitted.
                for v in ("v1_0", "v1_1", "v1_2", "v1_3"):
                    if v in toks and toks[toks.index(v) + 1].lower() in ("enable", "enabled", "true"):
                        p["versions"].append(v[1:].replace("_", "."))
                # cipherSuite1..N <suite> / cipherSuiteList <suite>
                for i, t in enumerate(toks):
                    if t.startswith("cipherSuite") and i + 1 < len(toks):
                        p["ciphers"].append(toks[i + 1])

            elif toks[1:4] == ["addressContext", "default", "zone"] and len(toks) >= 5:
                zone = toks[4]
                z = zones.setdefault(zone, {
                    "transport": None, "tls_profile": None, "keepalive": False,
                    "normalization": None, "codecs": [], "dtmf": None, "srtp": False})
                if "srtpCryptoProfile" in toks or "secureMediaProfile" in toks or "srtp" in toks:
                    z["srtp"] = True
                if "transportProtocolsAllowed" in toks:
                    val = toks[toks.index("transportProtocolsAllowed") + 1]
                    z["transport"] = {"sip-tls": "tls", "sip-tcp": "tcp",
                                      "sip-udp": "udp"}.get(val, val)
                if "tlsProfileName" in toks:
                    z["tls_profile"] = toks[toks.index("tlsProfileName") + 1]
                if "outputAdapterProfile" in toks:
                    z["normalization"] = toks[toks.index("outputAdapterProfile") + 1]
                if "sipOptions" in toks:
                    z["keepalive"] = True
                if "codec" in toks:
                    c = toks[toks.index("codec") + 1]
                    z["codecs"].append(_RIBBON_CODEC.get(c, c.upper()))
                if "dtmf" in toks:
                    d = toks[toks.index("dtmf") + 1]
                    z["dtmf"] = "rfc2833" if d in ("rtp-nte", "rfc2833") else d

            elif toks[1:4] == ["addressContext", "default", "media"]:
                if "mediaAddress" in toks:
                    media_ip = toks[toks.index("mediaAddress") + 1]
                if "symmetricRtp" in toks:
                    symmetric = toks[toks.index("symmetricRtp") + 1].lower() in ("enabled", "true")

        cfg.sbc_fqdn = fqdn

        # leaf cert: from the first tls profile that has a cert (Teams leg)
        leaf = None
        if any(p.get("cert") for p in tls_profiles.values()) or leaf_cert_file:
            leaf = Certificate(
                subject_cn=fqdn,
                sans=[fqdn] if fqdn else [],
                ekus=[],                         # filled by deep C pass from PEM
                source_file=leaf_cert_file,
                # Unknown until proven: when a real leaf PEM is supplied the deep
                # C pass computes chain completeness from the chain itself; absent
                # that, do not assert a complete chain we never inspected.
                # (COV-002 honesty: None, not a guessed True.)
                chain_complete=None,
            )

        for zone, z in zones.items():
            role = _role_for_zone(zone)
            ctx = None
            if (z["transport"] or "").lower() == "tls":
                prof = tls_profiles.get(z["tls_profile"] or "", {})
                vers = prof.get("versions") or []
                minv = min(vers, key=lambda s: tuple(int(x) for x in s.split("."))) if vers else None
                ctx = TlsContext(
                    name=z["tls_profile"] or f"{zone}-tls",
                    # Only assert mTLS from an actually-parsed TLS profile (where
                    # `authClient` was observed). If the zone references a profile
                    # we never parsed (prof == {}), it is unknown, not on.
                    # (COV-002 honesty: None, not a guessed True.)
                    mtls_enabled=prof.get("mtls"),
                    presented_cert=leaf,
                    trusted_root_ids=list(roots),
                    min_tls_version=minv,
                    cipher_suites=(prof.get("ciphers") or None),
                )
            cfg.sip_interfaces.append(SipInterface(
                name=zone,
                role=role,
                fqdn=fqdn if role == "teams" else None,
                tls_context=ctx,
                transport=z["transport"],
                options_keepalive=z["keepalive"],
                normalization_profile=z["normalization"],
                # Tristate: no codec lines on this trunk group -> None (not carried).
                offered_codecs=z["codecs"] or None,
                dtmf_method=z["dtmf"],
                srtp_enabled=z.get("srtp", False),
            ))

        if media_ip:
            cfg.media_realms.append(MediaRealm(
                name="default-media", advertised_public_ip=media_ip,
                symmetric_rtp=symmetric))

        cfg.raw_meta["parser"] = "ribbon/sbc-core"
        return cfg
