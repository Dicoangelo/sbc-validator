r"""
Real AudioCodes parameter-table .ini parser (the format a Mediant SBC actually
exports), plus a mapper from its tables to the vendor-neutral NormalizedConfig.

Real AudioCodes config is NOT the simplified [sip:Name] projection used by the
smoke-test samples. It is scalar params plus indexed parameter TABLES, per the
Mediant User's Manual (ver 7.6):

    EnableMediaSecurity = 1
    [ SIPInterface ]
    FORMAT Index = InterfaceName, ApplicationType, TLSContext, TCPPort, TLSPort;
    SIPInterface 0 = "Teams", 2, "Teams-TLS", 0, 5061;
    [ \SIPInterface ]

Direct Routing is expressed across several tables that reference each other:
  ProxyIP   -> the Teams proxy FQDNs (sip.pstnhub.microsoft.com ...) + transport
  ProxySet  -> groups ProxyIPs, sets keep-alive + TLS context
  SIPInterface -> transport/port + TLS context
  IPProfile -> SBCMediaSecurityBehaviour (SRTP), allowed coders group
  IPGroup   -> ties ProxySet + IPProfile + SIPInterface together; this is the "leg"
  CodersGroup0 -> the audio coder list

Honest limitation, straight from the manual: an AudioCodes .ini does NOT contain
the leaf certificate or the trust-store root CAs (those are imported certificate
files). So the mapped TLS context is marked introspectable=False and the C
validator reports "verify out-of-band" instead of false-claiming a missing
cert/trust store. Supply the PEM via the annotated `; sbc-validator: leaf-cert`
line to enable the deep cert checks.
"""
from __future__ import annotations

import re

from ..models import (
    Certificate, MediaRealm, NormalizedConfig, SipInterface, TlsContext,
)

# AudioCodes coder token -> normalized codec name
_CODER = {
    "g711ulaw": "PCMU", "g711alaw": "PCMA", "g722": "G722", "g729": "G729",
    "g729e": "G729", "silk": "SILK", "silknb": "SILK", "silkwb": "SILK", "opus": "OPUS",
}
# SBCMediaSecurityBehaviour: 0=as-is(passthrough), 1=SRTP(secured), 2=RTP, 3=both.
# SRTP is actually negotiated when it's 1 or 3 (or named Secured/Both/Mandatory).
_SRTP_BEHAVIOURS = {"1", "3", "secured", "both", "mandatory", "preferable"}


def _split_csv(s: str) -> list[str]:
    """Split a data line's value list on commas, respecting double-quoted strings."""
    out, cur, inq = [], [], False
    for ch in s:
        if ch == '"':
            inq = not inq
        elif ch == "," and not inq:
            out.append("".join(cur).strip().strip('"')); cur = []
            continue
        cur.append(ch)
    if cur:
        out.append("".join(cur).strip().strip('"'))
    return out


def parse_table_ini(text: str):
    """Return (globals: dict, tables: dict[str, list[dict]]).

    Tables are lists of row dicts keyed by their FORMAT column names (plus 'Index').
    """
    globals_: dict[str, str] = {}
    tables: dict[str, list[dict]] = {}
    leaf_cert_file = None

    m = re.search(r";\s*sbc-validator:\s*leaf-cert\s+(\S+)", text)
    if m:
        leaf_cert_file = m.group(1)

    cur_table = None
    cur_cols: list[str] = []
    buf = ""

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(";"):
            continue
        # table end
        if re.match(r"\[\s*\\", line):
            cur_table, cur_cols = None, []
            continue
        # table start: [ Name ]  (not the end form, handled above)
        mt = re.match(r"\[\s*([^\]\\]+?)\s*\]$", line)
        if mt and "=" not in line:
            cur_table = mt.group(1).strip()
            tables.setdefault(cur_table, [])
            cur_cols = []
            continue
        if cur_table:
            # accumulate until the statement-terminating ';'
            buf += " " + line
            if ";" not in buf:
                continue
            stmt, buf = buf.split(";", 1)[0].strip(), ""
            if stmt.upper().startswith("FORMAT"):
                cols = stmt.split("=", 1)[1] if "=" in stmt else ""
                cur_cols = [c.strip() for c in cols.split(",") if c.strip()]
                continue
            # data line: "<Table> <index> = v0, v1, ..."
            if "=" not in stmt:
                continue
            lhs, rhs = stmt.split("=", 1)
            idx = lhs.strip().split()[-1]
            vals = _split_csv(rhs.strip())
            row = {"Index": idx}
            for i, col in enumerate(cur_cols):
                if col == "Index":
                    continue
                vi = i - 1 if cur_cols and cur_cols[0] == "Index" else i
                if 0 <= vi < len(vals):
                    row[col] = vals[vi]
            tables[cur_table].append(row)
        else:
            if "=" in line:
                k, v = line.split("=", 1)
                globals_[k.strip()] = v.strip().strip('"')

    if leaf_cert_file:
        globals_["_leaf_cert_file"] = leaf_cert_file
    return globals_, tables


def _get(row: dict, *names, default=None):
    """Case-insensitive column lookup with aliases."""
    low = {k.lower(): v for k, v in row.items()}
    for n in names:
        if n.lower() in low:
            return low[n.lower()]
    return default


def is_table_ini(text: str) -> bool:
    head = text[:4000]
    return ("FORMAT Index" in head or re.search(r"\[\s*\\", head) is not None
            or re.search(r"\[\s*(SIPInterface|IPGroup|ProxySet|TLSContexts)\s*\]", head) is not None)


def map_to_config(text: str) -> NormalizedConfig:
    globals_, tables = parse_table_ini(text)
    cfg = NormalizedConfig(vendor="audiocodes")
    cfg.raw_meta["parser"] = "audiocodes/table-ini"

    enable_ms = str(globals_.get("EnableMediaSecurity", "0")).strip().lower() in ("1", "true")
    cfg.sbc_fqdn = globals_.get("SIPGatewayName") or globals_.get("SBCFQDN") or None

    # --- ProxySet index -> name, keepalive, tls context ---
    ps_name, ps_keepalive, ps_tls = {}, {}, {}
    for r in tables.get("ProxySet", []):
        idx = r.get("Index")
        name = _get(r, "ProxyName", "ProxySetName", "Name", default=idx)
        ps_name[str(idx)] = str(name)
        ka = _get(r, "ProxyKeepAliveType", "ProxyKeepAlive", "KeepAliveType", default="0")
        ps_keepalive[str(name)] = str(ka).strip().lower() not in ("0", "", "disable", "false")
        ps_tls[str(name)] = _get(r, "TLSContext", "TLSContextName", "TLSContextId")

    # --- ProxyIP rows -> per-ProxySet FQDNs + transport ---
    ps_fqdns, ps_transport = {}, {}
    for r in tables.get("ProxyIP", []):
        psid = _get(r, "ProxySetId", "ProxySetIndex", "ProxySetID", "ProxySet", default="")
        nm = ps_name.get(str(psid), str(psid))
        addr = _get(r, "IPAddress", "Address", "ProxyIPAddress", default="")
        ps_fqdns.setdefault(nm, []).append(addr)
        tt = str(_get(r, "TransportType", "Transport", default="")).strip().lower()
        if tt in ("2", "tls"):
            ps_transport[nm] = "tls"
        elif tt in ("1", "tcp"):
            ps_transport.setdefault(nm, "tcp")
        elif tt in ("0", "udp"):
            ps_transport.setdefault(nm, "udp")

    # --- SIPInterface name -> transport (from ports) + tls context ---
    si_tls, si_transport = {}, {}
    for r in tables.get("SIPInterface", []):
        name = _get(r, "InterfaceName", "Name", default=r.get("Index"))
        si_tls[str(name)] = _get(r, "TLSContext", "TLSContextName")
        tlsport = str(_get(r, "TLSPort", "TLSMutualPort", default="0")).strip()
        tcpport = str(_get(r, "TCPPort", default="0")).strip()
        si_transport[str(name)] = "tls" if tlsport not in ("0", "", "None") else (
            "tcp" if tcpport not in ("0", "", "None") else "udp")

    # --- IPProfile name -> srtp behaviour + coders group ---
    ipp_srtp, ipp_coders_ref = {}, {}
    for r in tables.get("IPProfile", []):
        name = _get(r, "ProfileName", "Name", default=r.get("Index"))
        beh = str(_get(r, "SBCMediaSecurityBehaviour", "SBCMediaSecurityBehavior",
                       default="0")).strip().lower()
        ipp_srtp[str(name)] = enable_ms and beh in _SRTP_BEHAVIOURS
        ipp_coders_ref[str(name)] = _get(r, "SBCAllowedAudioCodersGroupName",
                                         "AllowedAudioCodersGroupName", "CodersGroupName")

    # --- coders groups: group name -> [normalized codec] ---
    coders_by_group = {}
    for tname, rows in tables.items():
        if not (tname.lower().startswith("codersgroup") or "coders" in tname.lower()):
            continue
        for r in rows:
            grp = _get(r, "CodersGroupName", "Name", "AudioCodersGroupName", default=tname)
            coder = str(_get(r, "Coder", "Name", "CoderName", default="")).lower()
            norm = _CODER.get(coder)
            if norm:
                coders_by_group.setdefault(str(grp), []).append(norm)

    # --- IPGroup rows are the legs ---
    for ig in tables.get("IPGroup", []):
        name = _get(ig, "Name", "GroupName", default=ig.get("Index"))
        psname = str(_get(ig, "ProxySetName", "ProxySet", default=""))
        ippname = str(_get(ig, "IPProfileName", "IPProfile", default=""))
        siname = str(_get(ig, "SIPInterfaceName", "SIPInterface", default=""))

        fqdns = ps_fqdns.get(psname, [])
        is_teams = any("pstnhub.microsoft.com" in (f or "").lower() for f in fqdns)
        role = "teams" if is_teams else "carrier"

        transport = ps_transport.get(psname) or si_transport.get(siname)
        tls_ctx_name = ps_tls.get(psname) or si_tls.get(siname)
        ctx = None
        if (transport or "").lower() == "tls":
            ctx = TlsContext(
                name=str(tls_ctx_name or f"{name}-tls"),
                mtls_enabled=True,                 # Direct Routing uses mTLS
                presented_cert=(Certificate(source_file=globals_.get("_leaf_cert_file"))
                                if globals_.get("_leaf_cert_file") else None),
                trusted_root_ids=[],               # imported separately; not in the .ini
                introspectable=False,              # cert/trust not present in this source
            )
        cfg.sip_interfaces.append(SipInterface(
            name=str(name),
            role=role,
            fqdn=cfg.sbc_fqdn if role == "teams" else None,
            tls_context=ctx,
            transport=transport,
            options_keepalive=ps_keepalive.get(psname, False),
            offered_codecs=coders_by_group.get(ipp_coders_ref.get(ippname) or "", []),
            srtp_enabled=ipp_srtp.get(ippname, False),
        ))

    # --- media realms ---
    for r in tables.get("MediaRealm", []):
        cfg.media_realms.append(MediaRealm(
            name=str(_get(r, "MediaRealmName", "Name", default=r.get("Index"))),
            advertised_public_ip=_get(r, "IPv4IF", "IPAddress", "PublicIP", default=None) or None,
            symmetric_rtp=True,
        ))
    return cfg
