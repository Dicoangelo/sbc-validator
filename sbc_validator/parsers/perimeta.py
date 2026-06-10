"""
Metaswitch Perimeta parser — the fifth vendor (the carrier/SBCaaS ICP: 50+
operators run Teams Direct Routing on Perimeta per Metaswitch).

Parses the Perimeta CLI config style: `adjacency sip <Name>` blocks of indented
`keyword value` attributes. Grounded against three independent public configs
(verbatim syntax, fetched 2026-06-10):
  * MiaRec SIPREC integration guide  (full preset-access adjacency)
  * TransNexus ClearIP outbound guide (full preset-peering adjacency)
  * Award Consulting message-manipulation guide (edit-profiles / header-profiles)

Constructs read:
  * `adjacency sip <name>`                -> one SIP interface per adjacency
  * `signaling-peer <host>`               -> role: teams when *.pstnhub.microsoft.com
  * `mandated-transport` / `preferred-transport` / `listen-transports` -> transport
  * `interop > ping-enable` (+ `interval N`) -> SIP OPTIONS keep-alive + interval
  * `message-manipulation > edit-profiles inbound/outbound <list>` -> normalization
  * `signaling-local-port` / `signaling-peer-port` kept in raw_meta for explainability

Honest scope: Perimeta keeps TLS profiles, certificates, codec policy, and media
addresses OUTSIDE the adjacency block (system/profile level, not publicly
documented), so this parser emits tristate-None for codecs/SRTP/cert material and
maps TLS legs with introspectable=False — domain C says "verify out-of-band"
instead of false-claiming a missing trust store, and domain E stays silent rather
than false-firing NONE_OFFERED. The `tls` transport token follows the grounded
`mandated-transport <transport>` grammar (`tcp` shown verbatim in sources).
Widen coverage from real customer exports, never by guessing the long tail.
"""
from __future__ import annotations

import re

from ..models import NormalizedConfig, SipInterface, TlsContext
from .base import AbstractParser

_TRANSPORTS = ("tls", "tcp", "udp")


def _transport_of(tokens: list[str]) -> str | None:
    for t in tokens:
        if t.lower() in _TRANSPORTS:
            return t.lower()
    return None


class PerimetaParser(AbstractParser):
    vendor = "metaswitch_perimeta"

    @classmethod
    def sniff(cls, text: str) -> bool:
        return bool(re.search(r"^\s*adjacency\s+sip\s+\S", text, re.M))

    def parse(self, text: str) -> NormalizedConfig:
        cfg = NormalizedConfig(vendor=self.vendor)
        cfg.raw_meta["parser"] = "metaswitch_perimeta/cli"

        # Split into adjacency blocks: a block runs from its `adjacency sip` line
        # to the next one (or EOF). Names may contain spaces (TransNexus shows
        # `adjacency sip ClearIP Outbound`).
        starts = [(m.start(), m.group(1).strip())
                  for m in re.finditer(r"^\s*adjacency\s+sip\s+(.+?)\s*$", text, re.M)]
        for i, (pos, name) in enumerate(starts):
            end = starts[i + 1][0] if i + 1 < len(starts) else len(text)
            block = text[pos:end]
            lines = [ln.strip() for ln in block.splitlines()[1:] if ln.strip()]

            peer = transport = None
            keepalive = None            # tristate: ping-enable absent -> unknown
            interval = None
            norm_profiles: list[str] = []
            local_port = peer_port = None
            in_ping = False
            for ln in lines:
                toks = ln.split()
                key = toks[0].lower()
                if key == "signaling-peer" and len(toks) >= 2:
                    peer = toks[1].strip('"')
                elif key in ("mandated-transport", "preferred-transport",
                             "listen-transports"):
                    # precedence: mandated > preferred > listen (first hit wins
                    # per kind; mandated overrides whatever was seen before)
                    t = _transport_of(toks[1:])
                    if t and (transport is None or key == "mandated-transport"):
                        transport = t
                elif key == "ping-enable":
                    keepalive = True
                    in_ping = True
                    continue
                elif in_ping and key == "interval" and len(toks) >= 2:
                    try:
                        interval = int(toks[1])
                    except ValueError:
                        pass
                elif key == "edit-profiles" and len(toks) >= 3:
                    val = " ".join(toks[2:]).strip()
                    if val and val != '""':
                        norm_profiles.append(f"{toks[1]}:{val}")
                elif key == "signaling-local-port" and len(toks) >= 2:
                    local_port = toks[1]
                elif key == "signaling-peer-port" and len(toks) >= 2:
                    peer_port = toks[1]
                # leaving the ping-enable sub-block once a non-ping key appears
                if key not in ("ping-enable", "interval", "fail-count", "lifetime"):
                    in_ping = False

            role = "teams" if peer and "pstnhub.microsoft.com" in peer.lower() \
                else "carrier"
            ctx = None
            if transport == "tls":
                # TLS profiles/certs live outside the adjacency export: map the
                # context as non-introspectable so domain C reports
                # "verify out-of-band", never a false missing-trust-store CRITICAL.
                ctx = TlsContext(
                    name=f"{name}-tls",
                    mtls_enabled=True,          # Direct Routing over TLS is mutual
                    presented_cert=None,
                    trusted_root_ids=[],
                    introspectable=False,
                )
            cfg.sip_interfaces.append(SipInterface(
                name=name,
                role=role,
                fqdn=None,                       # not carried in adjacency exports
                tls_context=ctx,
                transport=transport,
                options_keepalive=keepalive,
                options_keepalive_interval=interval,
                normalization_profile=(", ".join(norm_profiles) or None),
                offered_codecs=None,             # codec policy is outside the adjacency
                dtmf_method=None,
                srtp_enabled=None,               # media-security policy not carried here
            ))
            cfg.raw_meta[f"adjacency:{name}"] = {
                "peer": peer, "local_port": local_port, "peer_port": peer_port,
            }
        return cfg
