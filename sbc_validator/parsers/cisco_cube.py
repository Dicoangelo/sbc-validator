"""
Cisco CUBE (IOS-XE) parser — the second vendor, proving the normalized model and
the A-E validators are genuinely vendor-agnostic.

Parses a real IOS-XE running-config export (not a re-skinned INI). It reads the
constructs a modern Microsoft Direct Routing CUBE actually uses:

  * hostname + `ip domain name`            -> SBC FQDN
  * `crypto pki trustpoint <name>` blocks  -> identity trustpoint + trusted roots
  * `crypto signaling default trustpoint`  -> which trustpoint presents the leaf
  * `voice class codec <id>` blocks        -> codec lists (Cisco tokens normalized)
  * `voice class tenant <id>` blocks       -> SIP interfaces (Teams / carrier legs)
  * `voice service voip > media-address`   -> media realm advertised address
  * annotation `! sbc-validator: leaf-cert <path>` -> real PEM for the deep C pass

Trust model note: in CUBE you trust a CA by creating a `crypto pki trustpoint`
for it, so every non-identity trustpoint name is treated as a trusted root id.
That maps cleanly onto the same `trusted_root_ids` the AudioCodes parser fills,
which is the whole point: validators never see vendor syntax.

Scope is deliberately the Direct Routing path, end to end. Widen construct
coverage from real customer exports rather than guessing the long tail.
"""
from __future__ import annotations

import re

from ..models import (
    Certificate, MediaRealm, NormalizedConfig, SipInterface, TlsContext,
)
from .base import AbstractParser

# Cisco codec token -> normalized codec name (matches ruleset E vocabulary).
_CODEC_MAP = {
    "g711ulaw": "PCMU",
    "g711alaw": "PCMA",
    "g722-64": "G722",
    "g722": "G722",
    "g729r8": "G729",
    "g729": "G729",
    "opus": "OPUS",
}


def _blocks(text: str):
    """Yield (header_line, [child_lines]) for IOS-XE indented blocks.

    A block header starts at column 0; its body is the following indented lines
    up to the next column-0 line or a bang separator.
    """
    lines = text.splitlines()
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        if line and not line.startswith((" ", "\t", "!")):
            header = line.rstrip()
            body = []
            i += 1
            while i < n and (lines[i].startswith((" ", "\t")) and lines[i].strip()):
                body.append(lines[i].strip())
                i += 1
            yield header, body
        else:
            i += 1


def _norm_codecs(child_lines: list[str]) -> list[str]:
    out = []
    for ln in child_lines:
        m = re.match(r"codec preference \d+\s+(\S+)", ln)
        if m:
            tok = m.group(1).lower()
            out.append(_CODEC_MAP.get(tok, tok.upper()))
    return out


class CiscoCubeParser(AbstractParser):
    vendor = "cisco_cube"

    @classmethod
    def sniff(cls, text: str) -> bool:
        return "dial-peer voice" in text or "voice service voip" in text \
            or "voice class tenant" in text

    def parse(self, text: str) -> NormalizedConfig:
        cfg = NormalizedConfig(vendor=self.vendor)

        hostname = None
        domain = None
        leaf_cert_file = None
        signaling_tp = None
        identity_subject_cn = None
        trustpoints: dict[str, dict] = {}     # name -> {subject_cn}
        codecs: dict[str, list[str]] = {}     # codec class id -> [normalized]
        tenants: list[dict] = []
        media_ip = None
        flow_around = False
        global_options_keepalive = False

        # annotation for the real leaf PEM (annotated export convention)
        m = re.search(r"!\s*sbc-validator:\s*leaf-cert\s+(\S+)", text)
        if m:
            leaf_cert_file = m.group(1)

        for header, body in _blocks(text):
            h = header.strip()

            if h.startswith("hostname "):
                hostname = h.split(None, 1)[1].strip()

            elif h.startswith("ip domain name "):
                domain = h.split("ip domain name ", 1)[1].strip()

            elif h.startswith("crypto signaling default trustpoint"):
                parts = h.split()
                signaling_tp = parts[-1]

            elif h.startswith("crypto pki trustpoint "):
                name = h.split("crypto pki trustpoint ", 1)[1].strip()
                subj_cn = None
                for ln in body:
                    sm = re.search(r"subject-name\s+.*cn=([^,\s]+)", ln, re.I)
                    if sm:
                        subj_cn = sm.group(1)
                trustpoints[name] = {"subject_cn": subj_cn}

            elif h.startswith("voice class codec "):
                cid = h.split("voice class codec ", 1)[1].strip()
                codecs[cid] = _norm_codecs(body)

            elif h.startswith("voice class tenant "):
                tid = h.split("voice class tenant ", 1)[1].strip()
                t = {"id": tid, "role": "unknown", "transport": None,
                     "options_keepalive": False, "codec_ref": None,
                     "sip_profiles": None, "dtmf": None, "sip_server": None,
                     "srtp": False}
                for ln in body:
                    low = ln.lower()
                    if low.startswith("description"):
                        d = ln.split(None, 1)[1].strip().lower() if len(ln.split(None, 1)) > 1 else ""
                        if "teams" in d:
                            t["role"] = "teams"
                        elif "carrier" in d or "pstn" in d or "itsp" in d:
                            t["role"] = "carrier"
                    elif low.startswith("sip-server"):
                        t["sip_server"] = ln.split(None, 1)[1].strip()
                        if "pstnhub.microsoft.com" in low:
                            t["role"] = "teams"
                    elif low.startswith("session transport"):
                        if "tls" in low:
                            t["transport"] = "tls"
                        elif "udp" in low:
                            t["transport"] = "udp"
                        else:
                            t["transport"] = "tcp"
                    elif low == "options-keepalive" or low.startswith("options-keepalive"):
                        t["options_keepalive"] = True
                    elif low.startswith("voice-class codec") or low.startswith("voice class codec"):
                        t["codec_ref"] = ln.split()[-1]
                    elif low.startswith("sip-profiles"):
                        t["sip_profiles"] = ln.split()[-1]
                    elif low.startswith("dtmf-relay"):
                        t["dtmf"] = "rfc2833" if "rtp-nte" in low else \
                                    ("info" if "sip-notify" in low or "sip-info" in low else "inband")
                    elif low.startswith("srtp"):          # 'srtp' or 'srtp-crypto N'
                        t["srtp"] = True
                tenants.append(t)

            elif h == "voice service voip":
                for ln in body:
                    low = ln.lower()
                    if low.startswith("media-address"):
                        mm = re.search(r"media-address\s+([0-9.]+)", ln)
                        if mm:
                            media_ip = mm.group(1)
                    elif "options-keepalive" in low:
                        global_options_keepalive = True
                    elif "flow-around" in low:
                        flow_around = True

        # ---- FQDN ---- (hostname, qualified with `ip domain name` if not already)
        if hostname:
            fqdn = hostname.lower()
            dom = (domain or "").lower()
            if dom and not fqdn.endswith("." + dom) and fqdn != dom:
                fqdn = f"{fqdn}.{dom}"
            cfg.sbc_fqdn = fqdn

        # ---- identity leaf cert + trusted roots ----
        identity_name = signaling_tp
        if identity_name and identity_name in trustpoints:
            identity_subject_cn = trustpoints[identity_name].get("subject_cn")
        leaf = None
        # build a leaf from what we can see; deep C pass overrides via PEM if present
        if identity_name:
            leaf = Certificate(
                subject_cn=identity_subject_cn or cfg.sbc_fqdn,
                sans=[identity_subject_cn] if identity_subject_cn else (
                    [cfg.sbc_fqdn] if cfg.sbc_fqdn else []),
                ekus=[],                       # unknown from config; PEM fills it
                source_file=leaf_cert_file,
                chain_complete=True,           # CUBE builds chain from trustpoints
            )
        # every non-identity trustpoint is a trusted root id
        trusted_roots = [name for name in trustpoints if name != identity_name]

        # ---- SIP interfaces from tenants ----
        any_keepalive = global_options_keepalive
        for t in tenants:
            ctx = None
            if (t["transport"] or "").lower() == "tls":
                ctx = TlsContext(
                    name=f"tenant{t['id']}-tls",
                    mtls_enabled=True,           # Direct Routing over TLS is mutual
                    presented_cert=leaf,
                    trusted_root_ids=list(trusted_roots),
                )
            cfg.sip_interfaces.append(SipInterface(
                name=f"tenant{t['id']}",
                role=t["role"],
                fqdn=cfg.sbc_fqdn if t["role"] == "teams" else None,
                tls_context=ctx,
                transport=t["transport"],
                options_keepalive=t["options_keepalive"] or any_keepalive,
                normalization_profile=t["sip_profiles"],
                offered_codecs=codecs.get(t["codec_ref"] or "", []),
                dtmf_method=t["dtmf"],
                srtp_enabled=t["srtp"],
            ))

        # ---- media realm ----
        if media_ip:
            cfg.media_realms.append(MediaRealm(
                name="voice-service-voip",
                advertised_public_ip=media_ip,
                symmetric_rtp=not flow_around,   # CUBE latches by default
            ))

        cfg.raw_meta["parser"] = "cisco_cube/ios-xe"
        return cfg
