"""
Generate small, wire-valid classic .pcap fixtures for the `explain` command.

These are synthetic (like the sample configs): hand-built Ethernet/IPv4/UDP
frames carrying real, correct SIP text and RTP bytes. They let the analyzer be
demoed and tested deterministically without shipping a customer's real capture.

    python samples/make_pcaps.py        # writes samples/*.pcap
"""
from __future__ import annotations

import socket
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent

SBC = "80.0.0.10"          # SBC public address (globally routable)
TEAMS = "52.112.0.10"      # a Microsoft Teams SIP proxy address
PRIVATE = "10.1.1.5"       # an internal/private address (non-routable)


def _ipv4_udp(src, dst, sport, dport, payload: bytes) -> bytes:
    udp = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    total = 20 + len(udp)
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, 0, 0x4000, 64, 17, 0,
                     socket.inet_aton(src), socket.inet_aton(dst)) + udp
    eth = b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01" + struct.pack(">H", 0x0800) + ip
    return eth


def _rtp(pt=0, seq=1, ssrc=0x11223344) -> bytes:
    # RTP v2 header + a little payload
    return struct.pack(">BBHII", 0x80, pt & 0x7F, seq, seq * 160, ssrc) + b"\x00" * 16


def write_pcap(path: Path, frames: list[bytes]):
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)  # LE, linktype Ethernet
    for i, f in enumerate(frames):
        out += struct.pack("<IIII", 1700000000 + i, i * 1000, len(f), len(f)) + f
    path.write_bytes(out)
    print(f"wrote {path.name}: {len(frames)} packets")


def _sip(first, call_id, cseq, extra_headers="", sdp: str = "") -> bytes:
    body = sdp.encode() if sdp else b""
    lines = [
        first,
        f"Via: SIP/2.0/UDP host;branch=z9hG4bK{call_id[:6]}",
        "From: <sip:+15551112222@contoso.com>;tag=a1",
        "To: <sip:+15553334444@pstnhub.microsoft.com>",
        f"Call-ID: {call_id}",
        f"CSeq: {cseq}",
    ]
    headers = "\r\n".join(lines) + "\r\n" + extra_headers
    if sdp:
        headers += "Content-Type: application/sdp\r\n"
    headers += f"Content-Length: {len(body)}\r\n\r\n"
    return headers.encode() + body


def _sdp(ip, codecs_pts, crypto=True):
    m = "m=audio 6000 RTP/SAVP " + " ".join(str(p) for p in codecs_pts) + "\r\n"
    rtpmap = {0: "PCMU/8000", 8: "PCMA/8000", 9: "G722/8000", 18: "G729/8000",
              101: "telephone-event/8000"}
    lines = [f"v=0", f"o=- 0 0 IN IP4 {ip}", "s=-", f"c=IN IP4 {ip}", "t=0 0", m.strip()]
    for p in codecs_pts:
        if p in rtpmap:
            lines.append(f"a=rtpmap:{p} {rtpmap[p]}")
    if crypto:
        lines.append("a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:abc123")
    lines.append("a=sendrecv")
    return "\r\n".join(lines) + "\r\n"


def clean_call():
    cid = "clean-call-001@contoso.com"
    f = []
    f.append(_ipv4_udp(SBC, TEAMS, 5060, 5060, _sip(
        "INVITE sip:+15553334444@pstnhub.microsoft.com SIP/2.0", cid, "1 INVITE",
        sdp=_sdp(SBC, [0, 8, 101]))))
    f.append(_ipv4_udp(TEAMS, SBC, 5060, 5060, _sip("SIP/2.0 100 Trying", cid, "1 INVITE")))
    f.append(_ipv4_udp(TEAMS, SBC, 5060, 5060, _sip("SIP/2.0 180 Ringing", cid, "1 INVITE")))
    f.append(_ipv4_udp(TEAMS, SBC, 5060, 5060, _sip(
        "SIP/2.0 200 OK", cid, "1 INVITE", sdp=_sdp(TEAMS, [0], crypto=True))))
    f.append(_ipv4_udp(SBC, TEAMS, 5060, 5060, _sip("ACK sip:teams SIP/2.0", cid, "1 ACK")))
    for i in range(6):                                  # RTP both directions -> two-way audio
        f.append(_ipv4_udp(SBC, TEAMS, 6000, 50000, _rtp(seq=i + 1)))
        f.append(_ipv4_udp(TEAMS, SBC, 50000, 6000, _rtp(seq=i + 1, ssrc=0x55667788)))
    f.append(_ipv4_udp(SBC, TEAMS, 5060, 5060, _sip("BYE sip:teams SIP/2.0", cid, "2 BYE")))
    f.append(_ipv4_udp(TEAMS, SBC, 5060, 5060, _sip("SIP/2.0 200 OK", cid, "2 BYE")))
    write_pcap(HERE / "clean_call.pcap", f)


def reject_488():
    cid = "reject-488-001@contoso.com"
    f = []
    f.append(_ipv4_udp(SBC, TEAMS, 5060, 5060, _sip(
        "INVITE sip:+15553334444@pstnhub.microsoft.com SIP/2.0", cid, "1 INVITE",
        sdp=_sdp(SBC, [18]))))                          # offers only G729
    f.append(_ipv4_udp(TEAMS, SBC, 5060, 5060, _sip("SIP/2.0 100 Trying", cid, "1 INVITE")))
    f.append(_ipv4_udp(TEAMS, SBC, 5060, 5060, _sip("SIP/2.0 488 Not Acceptable Here", cid, "1 INVITE")))
    f.append(_ipv4_udp(SBC, TEAMS, 5060, 5060, _sip("ACK sip:teams SIP/2.0", cid, "1 ACK")))
    write_pcap(HERE / "reject_488.pcap", f)


def one_way_audio():
    # Teams calls the SBC; the SBC answers advertising a PRIVATE media address.
    cid = "one-way-001@contoso.com"
    f = []
    f.append(_ipv4_udp(TEAMS, SBC, 5060, 5060, _sip(
        "INVITE sip:+15551112222@contoso.com SIP/2.0", cid, "1 INVITE", sdp=_sdp(TEAMS, [0, 8]))))
    f.append(_ipv4_udp(SBC, TEAMS, 5060, 5060, _sip("SIP/2.0 100 Trying", cid, "1 INVITE")))
    f.append(_ipv4_udp(SBC, TEAMS, 5060, 5060, _sip("SIP/2.0 180 Ringing", cid, "1 INVITE")))
    f.append(_ipv4_udp(SBC, TEAMS, 5060, 5060, _sip(
        "SIP/2.0 200 OK", cid, "1 INVITE", sdp=_sdp(PRIVATE, [0]))))   # private c-line
    f.append(_ipv4_udp(TEAMS, SBC, 5060, 5060, _sip("ACK sip:sbc SIP/2.0", cid, "1 ACK")))
    for i in range(6):                                  # RTP only one direction
        f.append(_ipv4_udp(TEAMS, SBC, 50000, 6000, _rtp(seq=i + 1)))
    write_pcap(HERE / "one_way_audio.pcap", f)


if __name__ == "__main__":
    clean_call()
    reject_488()
    one_way_audio()
