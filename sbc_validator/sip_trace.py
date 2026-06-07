"""
SIP/RTP call analysis from a packet capture: reconstruct the SIP ladder and
explain, in plain English, what happened and why a call failed.

This is the post-mortem twin of call_sim.py. call_sim predicts a call from static
config before deployment; this reads what actually happened on the wire and maps
the failure back to the same domains (B/C/D/E) so the diagnosis points straight at
the config fix. Deterministic and offline: it parses captured bytes, runs no LLM,
and originates no traffic.

Scope: SIP over UDP (full message + SDP parsing), RTP flow direction (one-way
audio detection), and a best-effort note for TLS-encrypted SIP on TCP/5061.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Optional

from .pcap import Packet, read_packets

_METHODS = ("INVITE", "ACK", "BYE", "CANCEL", "OPTIONS", "REGISTER", "INFO",
            "UPDATE", "PRACK", "SUBSCRIBE", "NOTIFY", "REFER", "MESSAGE")
# Cisco codec/payload-type number -> name for SDP rtpmap-less static PTs
_STATIC_PT = {0: "PCMU", 8: "PCMA", 9: "G722", 18: "G729", 13: "CN", 101: "telephone-event"}
_RESPONSE_CAUSE = {
    "401": ("auth", "Teams/peer demanded authentication (digest challenge)."),
    "403": ("B", "Forbidden: signaling rejected (often transport/identity/policy)."),
    "404": ("routing", "Not Found: the dialed number/route does not exist."),
    "407": ("auth", "Proxy authentication required."),
    "408": ("B", "Request Timeout: no answer from the next hop (signaling unreachable)."),
    "480": ("routing", "Temporarily Unavailable: endpoint not registered/available."),
    "486": ("ok", "Busy Here: callee was busy (not a config fault)."),
    "488": ("E", "Not Acceptable Here: SDP/codec negotiation failed (no common codec)."),
    "500": ("B", "Server Internal Error on the far side."),
    "503": ("B", "Service Unavailable: peer overloaded or down."),
    "603": ("ok", "Declined by the callee."),
}


def _is_sip(payload: bytes) -> bool:
    head = payload[:16]
    if head.startswith(b"SIP/2.0"):
        return True
    return any(head.startswith(m.encode() + b" ") for m in _METHODS)


@dataclass
class SipMsg:
    ts: float
    src: str
    dst: str
    first_line: str
    method: Optional[str]
    status: Optional[str]
    call_id: str
    cseq: str
    codecs: list[str] = field(default_factory=list)   # from SDP if present
    media_ip: Optional[str] = None                    # SDP c= line
    has_srtp: bool = False                             # SDP a=crypto present
    leaked: list = field(default_factory=list)        # [(header, private_ip)] topology leaks


def _parse_sip(pkt: Packet) -> Optional[SipMsg]:
    try:
        text = pkt.payload.decode("utf-8", "replace")
    except Exception:
        return None
    lines = text.split("\r\n")
    if not lines or not lines[0]:
        return None
    first = lines[0].strip()
    method = status = None
    if first.startswith("SIP/2.0"):
        m = re.match(r"SIP/2\.0\s+(\d{3})", first)
        status = m.group(1) if m else None
    else:
        method = first.split(" ", 1)[0]
        if method not in _METHODS:
            return None
    hdr = {}
    body_idx = len(lines)
    for i, ln in enumerate(lines[1:], 1):
        if ln == "":
            body_idx = i + 1
            break
        if ":" in ln:
            k, v = ln.split(":", 1)
            hdr[k.strip().lower()] = v.strip()
    body = "\r\n".join(lines[body_idx:])

    codecs, media_ip, has_srtp = [], None, False
    if "application/sdp" in hdr.get("content-type", "").lower() or "m=audio" in body:
        for bl in body.split("\r\n"):
            if bl.startswith("c=") and "IP" in bl:
                parts = bl.split()
                media_ip = parts[-1] if parts else None
            elif bl.startswith("m=audio"):
                for tok in bl.split()[3:]:
                    if tok.isdigit() and int(tok) in _STATIC_PT:
                        codecs.append(_STATIC_PT[int(tok)])
            elif bl.lower().startswith("a=rtpmap:"):
                mm = re.match(r"a=rtpmap:\d+\s+([A-Za-z0-9.\-]+)/", bl)
                if mm:
                    name = mm.group(1).upper().replace("-", "")
                    name = {"PCMU": "PCMU", "PCMA": "PCMA", "G722": "G722",
                            "G729": "G729", "OPUS": "OPUS", "SILK": "SILK",
                            "TELEPHONEEVENT": "telephone-event"}.get(name, mm.group(1))
                    if name not in codecs:
                        codecs.append(name)
            elif bl.lower().startswith("a=crypto:"):
                has_srtp = True
    # de-dup preserve order, drop telephone-event/CN from the "codecs" headline
    seen, clean = set(), []
    for c in codecs:
        if c in ("telephone-event", "CN") or c in seen:
            continue
        seen.add(c); clean.append(c)
    # topology-hiding check: private/internal IPs leaking in signaling headers
    leaked = []
    for hname in ("contact", "via", "record-route", "p-asserted-identity"):
        for ip in re.findall(r"\d{1,3}(?:\.\d{1,3}){3}", hdr.get(hname, "")):
            if _non_routable(ip):
                leaked.append((hname, ip))

    return SipMsg(pkt.ts, pkt.src_ip, pkt.dst_ip, first, method, status,
                  hdr.get("call-id", "?"), hdr.get("cseq", ""), clean, media_ip, has_srtp, leaked)


def _non_routable(ip: Optional[str]) -> bool:
    try:
        return ip is not None and not ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def _looks_rtp(pkt: Packet) -> bool:
    p = pkt.payload
    if pkt.proto != "udp" or len(p) < 12:
        return False
    if (p[0] & 0xC0) != 0x80:        # RTP version 2
        return False
    return 5060 not in (pkt.src_port, pkt.dst_port) and 5061 not in (pkt.src_port, pkt.dst_port)


@dataclass
class Diagnosis:
    code: str                # e.g. "REJECTED_488", "ONE_WAY_AUDIO", "CONNECTED", ...
    domain: str              # B/C/D/E/ok/... ties back to the validator
    headline: str
    detail: str
    fix: str


@dataclass
class CallAnalysis:
    call_id: str
    ladder: list[str]
    outcome: str
    diagnoses: list[Diagnosis]
    offered_codecs: list[str]
    answered_codecs: list[str]


def analyze(path: str) -> dict:
    pkts = read_packets(path)
    sip = [m for m in (_parse_sip(p) for p in pkts if _is_sip(p.payload)) if m]
    rtp_flows = {}                                   # (src,dst) -> count
    for p in pkts:
        if _looks_rtp(p):
            rtp_flows[(p.src_ip, p.dst_ip)] = rtp_flows.get((p.src_ip, p.dst_ip), 0) + 1
    tls_alert = any(p.proto == "tcp" and p.payload[:1] == b"\x15"
                    and (p.src_port == 5061 or p.dst_port == 5061) for p in pkts)
    tls_seen = any(p.proto == "tcp" and p.payload[:1] in (b"\x16", b"\x15")
                   and (p.src_port == 5061 or p.dst_port == 5061) for p in pkts)

    # group SIP by Call-ID
    calls: dict[str, list[SipMsg]] = {}
    for m in sip:
        calls.setdefault(m.call_id, []).append(m)

    analyses = []
    for cid, msgs in calls.items():
        msgs.sort(key=lambda m: m.ts)
        ladder, offered, answered = [], [], []
        invite_final = None
        for m in msgs:
            label = m.method or f"{m.status} {m.first_line.split(' ',2)[-1]}"
            extra = ""
            if m.codecs:
                extra = f"  SDP: {','.join(m.codecs)}" + (" +SRTP" if m.has_srtp else "")
                if m.method == "INVITE" and not offered:
                    offered = m.codecs
                if m.status == "200" and not answered:
                    answered = m.codecs
            ladder.append(f"{m.src} -> {m.dst}  {label}{extra}")
            if m.status and m.cseq.upper().endswith("INVITE") and int(m.status) >= 200:
                invite_final = invite_final or m

        diags: list[Diagnosis] = []
        outcome = "UNKNOWN"
        has_invite = any(m.method == "INVITE" for m in msgs)
        has_options = any(m.method == "OPTIONS" for m in msgs)

        if invite_final is not None:
            code = invite_final.status
            if code == "200":
                outcome = "CONNECTED"
                # one-way audio: 200 OK SDP advertises a private media IP, or RTP
                # flows are observed in only one direction.
                ans_ip = next((m.media_ip for m in msgs if m.status == "200" and m.media_ip), None)
                directions = set(rtp_flows)
                one_way = bool(rtp_flows) and len({d[0] for d in directions}) < 2
                if _non_routable(ans_ip):
                    outcome = "ONE_WAY_AUDIO"
                    diags.append(Diagnosis(
                        "ONE_WAY_AUDIO", "D",
                        "Call connected but media address is private/non-routable",
                        f"The 200 OK SDP advertised media at {ans_ip}, which is not "
                        "globally routable. Remote RTP cannot return.",
                        "Advertise the public NAT media address and enable symmetric RTP "
                        "(validator domain D)."))
                elif one_way:
                    outcome = "ONE_WAY_AUDIO"
                    diags.append(Diagnosis(
                        "ONE_WAY_AUDIO", "D",
                        "Call connected but RTP flowed in only one direction",
                        f"RTP observed {list(rtp_flows.values())} packets one way only; "
                        "the return media path is broken.",
                        "Check NAT/media address and symmetric RTP (validator domain D)."))
                else:
                    diags.append(Diagnosis(
                        "CONNECTED", "ok", "Call connected with two-way media",
                        f"INVITE -> 200 OK; codec {','.join(answered) or 'negotiated'}; "
                        f"RTP flows: {len(rtp_flows)}.", "None."))
            else:
                dom, why = _RESPONSE_CAUSE.get(code, ("B", f"Call failed with SIP {code}."))
                outcome = "REJECTED_" + code
                fix = {
                    "E": "Add a Teams-supported codec to the offer (validator domain E).",
                    "B": "Check transport (TLS), OPTIONS keep-alive, and signaling reachability (domain B).",
                    "auth": "Configure SIP digest credentials for the trunk.",
                    "routing": "Check the dial plan / number routing.",
                    "ok": "No config change: this is a normal call-clearing response.",
                }.get(dom, "Review the trunk configuration.")
                head = f"INVITE rejected with SIP {code}"
                if code == "488" and offered:
                    why += f" Offered codecs were {','.join(offered)}."
                diags.append(Diagnosis(outcome, dom, head, why, fix))
        elif has_invite:
            outcome = "NO_ANSWER"
            diags.append(Diagnosis(
                "NO_ANSWER", "B", "INVITE sent but no final response captured",
                "The INVITE got no 2xx/4xx/5xx/6xx. The next hop is likely unreachable "
                "or silently dropping signaling.",
                "Verify signaling reachability, transport (TLS), and firewall/routing (domain B)."))
        elif has_options:
            answered_opts = any(m.status == "200" and m.cseq.upper().endswith("OPTIONS") for m in msgs)
            if answered_opts:
                outcome = "OPTIONS_OK"
                diags.append(Diagnosis("OPTIONS_OK", "ok",
                    "SIP OPTIONS keep-alive answered (200 OK)",
                    "Signaling path is healthy.", "None."))
            else:
                outcome = "OPTIONS_UNANSWERED"
                diags.append(Diagnosis("OPTIONS_UNANSWERED", "B",
                    "SIP OPTIONS sent but not answered",
                    "Teams marks the SBC down when OPTIONS go unanswered.",
                    "Enable/repair OPTIONS keep-alive and check transport (domain B)."))

        # topology hiding: private IPs exposed in signaling headers (domain F)
        leaks = sorted({(h, ip) for m in msgs for (h, ip) in m.leaked})
        if leaks:
            diags.append(Diagnosis(
                "TOPOLOGY_LEAK", "F",
                "Internal/private IP exposed in SIP signaling (topology leak)",
                "Private addresses appeared in signaling headers crossing the border: "
                + ", ".join(f"{ip} in {h}" for h, ip in leaks)
                + ". A B2BUA should hide internal topology; exposing it aids attackers "
                "and can break routing.",
                "Enable topology hiding / header manipulation so Contact, Via, and "
                "Record-Route present only the public FQDN/IP."))

        analyses.append(CallAnalysis(cid, ladder, outcome, diags, offered, answered))

    top_diags = []
    if tls_alert:
        top_diags.append(Diagnosis(
            "TLS_HANDSHAKE_FAILED", "C", "TLS alert observed on SIP/TLS (port 5061)",
            "An encrypted SIP connection produced a TLS alert: the handshake failed, "
            "typically an untrusted root CA or an invalid/expired SBC certificate.",
            "Fix the trust store / certificate (validator domain C, the 2026 CA wedge)."))
    elif tls_seen and not sip:
        top_diags.append(Diagnosis(
            "ENCRYPTED_SIP", "C", "SIP is TLS-encrypted (port 5061); payload not readable",
            "Only the TLS handshake is visible. Capture on the SBC's internal/decrypted "
            "leg, or export keys, to read the SIP exchange.", "None (informational)."))

    return {
        "file": path,
        "packets": len(pkts),
        "sip_messages": len(sip),
        "rtp_flows": [{"from": s, "to": d, "packets": n} for (s, d), n in rtp_flows.items()],
        "tls": {"seen": tls_seen, "alert": tls_alert},
        "top_diagnoses": [vars(d) for d in top_diags],
        "calls": [{
            "call_id": a.call_id, "outcome": a.outcome, "ladder": a.ladder,
            "offered_codecs": a.offered_codecs, "answered_codecs": a.answered_codecs,
            "diagnoses": [vars(d) for d in a.diagnoses],
        } for a in analyses],
    }
