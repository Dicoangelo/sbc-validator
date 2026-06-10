"""
Synthetic labeled SIP-capture corpus for the on-prem explainer POC.

Pipeline proof, end-to-end, before any customer capture exists:
  jittered scenario -> wire-valid .pcap -> the REAL sbc_validator.sip_trace parser
  -> sip_tokenizer (normalized, privacy-safe) -> labeled JSONL corpus.

Frame builders adapted from samples/make_pcaps.py (same wire format), extended with
controllable per-frame timestamps so the tokenizer's GAP buckets see realistic timing.

Five classes (each maps to a validator domain the explainer must name):
  CLEAN            healthy two-way call            (domain ok)
  REJECT_488       codec not acceptable            (domain E)
  ONE_WAY_AUDIO    private SDP c= line, one-way RTP (domain D)
  TOPOLOGY_LEAK    private IP in Contact header     (domain F)
  OPTIONS_BLACKHOLE keepalives sent, never answered (domain B — the CallTower case)

Usage (from this directory, repo venv so sbc_validator imports):
  ../../../../.venv/bin/python make_corpus.py --per-class 100 --out corpus.jsonl
"""
from __future__ import annotations

import argparse
import json
import random
import socket
import struct
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(REPO))

from sbc_validator.pcap import read_packets                      # noqa: E402
from sbc_validator.sip_trace import (_is_sip, _parse_sip, _looks_rtp, _MIN_RTP,  # noqa: E402
                                     _fatal_tls_alert)
from sip_tokenizer import tokenize_call                          # noqa: E402


# ---------- wire builders (adapted from samples/make_pcaps.py, ts-controllable) ----

def _ipv4_udp(src, dst, sport, dport, payload: bytes) -> bytes:
    udp = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    total = 20 + len(udp)
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, 0, 0x4000, 64, 17, 0,
                     socket.inet_aton(src), socket.inet_aton(dst)) + udp
    return (b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01"
            + struct.pack(">H", 0x0800) + ip)


def _rtp(pt=0, seq=1, ssrc=0x11223344) -> bytes:
    return struct.pack(">BBHII", 0x80, pt & 0x7F, seq, seq * 160, ssrc) + b"\x00" * 16


def _ipv4_tcp(src, dst, sport, dport, payload: bytes) -> bytes:
    # Minimal 20-byte TCP header (data offset 5, PSH+ACK); the reader keys on
    # ports + data offset only, checksums unvalidated.
    tcp = struct.pack(">HHIIBBHHH", sport, dport, 1, 1, 5 << 4, 0x18, 65535, 0, 0) + payload
    total = 20 + len(tcp)
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, 0, 0x4000, 64, 6, 0,
                     socket.inet_aton(src), socket.inet_aton(dst)) + tcp
    return (b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01"
            + struct.pack(">H", 0x0800) + ip)


def _sip(first, call_id, cseq, extra_headers="", sdp: str = "") -> bytes:
    body = sdp.encode() if sdp else b""
    lines = [first,
             f"Via: SIP/2.0/UDP host;branch=z9hG4bK{call_id[:6]}",
             "From: <sip:+15551112222@contoso.com>;tag=a1",
             "To: <sip:+15553334444@pstnhub.microsoft.com>",
             f"Call-ID: {call_id}", f"CSeq: {cseq}"]
    headers = "\r\n".join(lines) + "\r\n" + extra_headers
    if sdp:
        headers += "Content-Type: application/sdp\r\n"
    headers += f"Content-Length: {len(body)}\r\n\r\n"
    return headers.encode() + body


def _sdp(ip, codecs_pts, crypto=True):
    rtpmap = {0: "PCMU/8000", 8: "PCMA/8000", 9: "G722/8000", 18: "G729/8000",
              101: "telephone-event/8000"}
    m = "m=audio 6000 RTP/SAVP " + " ".join(str(p) for p in codecs_pts)
    lines = ["v=0", f"o=- 0 0 IN IP4 {ip}", "s=-", f"c=IN IP4 {ip}", "t=0 0", m]
    for p in codecs_pts:
        if p in rtpmap:
            lines.append(f"a=rtpmap:{p} {rtpmap[p]}")
    if crypto:
        lines.append("a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:abc123")
    lines.append("a=sendrecv")
    return "\r\n".join(lines) + "\r\n"


def write_pcap_ts(path: Path, frames: list[tuple[float, bytes]]):
    """Classic pcap with explicit per-frame timestamps (seconds, float)."""
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for ts, f in frames:
        sec, usec = int(ts), int((ts - int(ts)) * 1_000_000)
        out += struct.pack("<IIII", sec, usec, len(f), len(f)) + f
    path.write_bytes(out)


# ---------- jittered scenarios ----------------------------------------------------

def _jig(rng: random.Random):
    """Per-sample jittered parameters."""
    sbc = f"{rng.choice([81, 85, 93, 198, 203])}.{rng.randint(1, 250)}.{rng.randint(1, 250)}.{rng.randint(2, 250)}"
    teams = f"52.{rng.randint(112, 115)}.{rng.randint(0, 250)}.{rng.randint(2, 250)}"
    private = rng.choice([f"10.{rng.randint(0, 250)}.{rng.randint(0, 250)}.{rng.randint(2, 250)}",
                          f"192.168.{rng.randint(0, 250)}.{rng.randint(2, 250)}"])
    cid = f"call-{rng.randrange(16**8):08x}@contoso.com"
    t0 = 1700000000 + rng.uniform(0, 1e6)
    step = lambda lo=0.02, hi=0.3: rng.uniform(lo, hi)  # noqa: E731
    return sbc, teams, private, cid, t0, step


def clean(rng):
    sbc, teams, _, cid, t, dt = _jig(rng)
    codecs = rng.choice([[0, 8, 101], [0, 101], [0, 8, 9, 101]])
    fr = [(t, _ipv4_udp(sbc, teams, 5060, 5060, _sip(
        "INVITE sip:+15553334444@pstnhub.microsoft.com SIP/2.0", cid, "1 INVITE",
        sdp=_sdp(sbc, codecs))))]
    t += dt(); fr.append((t, _ipv4_udp(teams, sbc, 5060, 5060, _sip("SIP/2.0 100 Trying", cid, "1 INVITE"))))
    t += dt(0.2, 2.5); fr.append((t, _ipv4_udp(teams, sbc, 5060, 5060, _sip("SIP/2.0 180 Ringing", cid, "1 INVITE"))))
    t += dt(0.3, 3.0); fr.append((t, _ipv4_udp(teams, sbc, 5060, 5060, _sip(
        "SIP/2.0 200 OK", cid, "1 INVITE", sdp=_sdp(teams, [codecs[0]])))))
    t += dt(); fr.append((t, _ipv4_udp(sbc, teams, 5060, 5060, _sip("ACK sip:teams SIP/2.0", cid, "1 ACK"))))
    for i in range(rng.randint(_MIN_RTP + 1, 10)):
        t += 0.02
        fr.append((t, _ipv4_udp(sbc, teams, 6000, 50000, _rtp(seq=i + 1))))
        fr.append((t + 0.001, _ipv4_udp(teams, sbc, 50000, 6000, _rtp(seq=i + 1, ssrc=0x5566))))
    return fr, cid


def reject_488(rng):
    sbc, teams, _, cid, t, dt = _jig(rng)
    fr = [(t, _ipv4_udp(sbc, teams, 5060, 5060, _sip(
        "INVITE sip:+15553334444@pstnhub.microsoft.com SIP/2.0", cid, "1 INVITE",
        sdp=_sdp(sbc, [18]))))]                      # G729-only offer
    t += dt(); fr.append((t, _ipv4_udp(teams, sbc, 5060, 5060, _sip("SIP/2.0 100 Trying", cid, "1 INVITE"))))
    t += dt(0.1, 1.0); fr.append((t, _ipv4_udp(teams, sbc, 5060, 5060, _sip(
        "SIP/2.0 488 Not Acceptable Here", cid, "1 INVITE"))))
    t += dt(); fr.append((t, _ipv4_udp(sbc, teams, 5060, 5060, _sip("ACK sip:teams SIP/2.0", cid, "1 ACK"))))
    return fr, cid


def one_way_audio(rng):
    sbc, teams, private, cid, t, dt = _jig(rng)
    fr = [(t, _ipv4_udp(teams, sbc, 5060, 5060, _sip(
        "INVITE sip:+15551112222@contoso.com SIP/2.0", cid, "1 INVITE", sdp=_sdp(teams, [0, 8]))))]
    t += dt(); fr.append((t, _ipv4_udp(sbc, teams, 5060, 5060, _sip("SIP/2.0 100 Trying", cid, "1 INVITE"))))
    t += dt(0.2, 2.0); fr.append((t, _ipv4_udp(sbc, teams, 5060, 5060, _sip("SIP/2.0 180 Ringing", cid, "1 INVITE"))))
    t += dt(0.3, 2.0); fr.append((t, _ipv4_udp(sbc, teams, 5060, 5060, _sip(
        "SIP/2.0 200 OK", cid, "1 INVITE", sdp=_sdp(private, [0])))))   # private c=
    t += dt(); fr.append((t, _ipv4_udp(teams, sbc, 5060, 5060, _sip("ACK sip:sbc SIP/2.0", cid, "1 ACK"))))
    for i in range(rng.randint(_MIN_RTP + 1, 10)):                       # one direction only
        t += 0.02
        fr.append((t, _ipv4_udp(teams, sbc, 50000, 6000, _rtp(seq=i + 1))))
    return fr, cid


def topology_leak(rng):
    sbc, teams, private, cid, t, dt = _jig(rng)
    contact = f"Contact: <sip:+15551112222@{private}:5060>\r\n"
    fr = [(t, _ipv4_udp(sbc, teams, 5060, 5060, _sip(
        "INVITE sip:+15553334444@pstnhub.microsoft.com SIP/2.0", cid, "1 INVITE",
        extra_headers=contact, sdp=_sdp(sbc, [0, 8]))))]
    t += dt(); fr.append((t, _ipv4_udp(teams, sbc, 5060, 5060, _sip("SIP/2.0 100 Trying", cid, "1 INVITE"))))
    t += dt(0.3, 2.0); fr.append((t, _ipv4_udp(teams, sbc, 5060, 5060, _sip(
        "SIP/2.0 200 OK", cid, "1 INVITE", sdp=_sdp(teams, [0])))))
    t += dt(); fr.append((t, _ipv4_udp(sbc, teams, 5060, 5060, _sip("ACK sip:teams SIP/2.0", cid, "1 ACK"))))
    for i in range(rng.randint(_MIN_RTP + 1, 8)):
        t += 0.02
        fr.append((t, _ipv4_udp(sbc, teams, 6000, 50000, _rtp(seq=i + 1))))
        fr.append((t + 0.001, _ipv4_udp(teams, sbc, 50000, 6000, _rtp(seq=i + 1, ssrc=0x5566))))
    return fr, cid


def options_blackhole(rng):
    """OPTIONS keepalives sent into the void — the CallTower silent-deactivation case."""
    sbc, teams, _, cid, t, _ = _jig(rng)
    fr = []
    for i in range(rng.randint(2, 4)):
        fr.append((t, _ipv4_udp(sbc, teams, 5060, 5060, _sip(
            f"OPTIONS sip:sip.pstnhub.microsoft.com SIP/2.0", cid, f"{i+1} OPTIONS"))))
        t += rng.uniform(55, 175)                    # the 60-180s keepalive window, unanswered
    return fr, cid


def tls_handshake_failed(rng):
    """The 2026 CA wedge itself (domain C): TLS ClientHello answered by a fatal
    alert on 5061; the call is cryptographically blocked from ever starting."""
    sbc, teams, _, cid, t, dt = _jig(rng)
    desc = rng.choice([42, 45, 46, 48, 70])     # bad_cert/expired/unknown/unknown_ca/version
    hello = bytes([0x16, 0x03, 0x01, 0x00, 0x30]) + bytes(48)     # ClientHello-shaped
    alert = bytes([0x15, 0x03, 0x03, 0x00, 0x02, 0x02, desc])     # fatal alert record
    eph = rng.randint(20000, 60000)
    fr = [(t, _ipv4_tcp(sbc, teams, eph, 5061, hello))]
    t += dt(0.02, 0.4)
    fr.append((t, _ipv4_tcp(teams, sbc, 5061, eph, alert)))
    return fr, cid


SCENARIOS = {
    "CLEAN": clean,
    "REJECT_488": reject_488,
    "ONE_WAY_AUDIO": one_way_audio,
    "TOPOLOGY_LEAK": topology_leak,
    "OPTIONS_BLACKHOLE": options_blackhole,
    "TLS_HANDSHAKE_FAILED": tls_handshake_failed,
}


# ---------- parse-with-the-real-engine + tokenize ---------------------------------

def pcap_to_tokens(path: str) -> list[str]:
    """Mirror sip_trace.analyze()'s grouping, emit tokens for the (single) call."""
    pkts = read_packets(path)
    msgs = [m for m in (_parse_sip(p) for p in pkts if _is_sip(p.payload)) if m]
    rtp_counts: dict = {}
    for p in pkts:
        if _looks_rtp(p):
            k = (p.src_ip, p.src_port, p.dst_ip, p.dst_port)
            rtp_counts[k] = rtp_counts.get(k, 0) + 1
    flows = {k for k, n in rtp_counts.items() if n >= _MIN_RTP}
    one_way = None
    if flows:
        one_way = any((d_ip, d_port, s_ip, s_port) not in flows
                      for (s_ip, s_port, d_ip, d_port) in flows)
    alerts = [c for c in (_fatal_tls_alert(p) for p in pkts) if c is not None]
    tc = tokenize_call(msgs, tls_alert_code=alerts[0] if alerts else None,
                       rtp_oneway=one_way)
    return tc.tokens


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-class", type=int, default=100)
    ap.add_argument("--out", default="corpus.jsonl")
    ap.add_argument("--seed", type=int, default=2026)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    out_path = Path(args.out)
    n_written = 0
    with tempfile.TemporaryDirectory() as td, out_path.open("w") as out:
        for label, builder in SCENARIOS.items():
            for i in range(args.per_class):
                frames, cid = builder(rng)
                p = Path(td) / f"{label}_{i}.pcap"
                write_pcap_ts(p, frames)
                tokens = pcap_to_tokens(str(p))
                # privacy gate on every sample: the real call-id must not survive
                blob = " ".join(tokens)
                assert cid not in blob, f"call-id leaked for {label}_{i}"
                out.write(json.dumps({"label": label, "tokens": tokens}) + "\n")
                n_written += 1
    print(f"wrote {out_path}: {n_written} labeled calls "
          f"({args.per_class} x {len(SCENARIOS)} classes), parsed by the real sip_trace engine")


if __name__ == "__main__":
    main()
