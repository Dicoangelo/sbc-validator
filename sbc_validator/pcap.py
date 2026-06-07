"""
Minimal classic-pcap reader (pure stdlib, no Wireshark/tshark/scapy dependency).

Reads a classic .pcap file and yields L4 payloads with their IP/port/proto, so
the SIP/RTP analyzer can work entirely offline and inside the trust boundary.
Scope is deliberate and honest: classic pcap (not pcapng), link types Ethernet /
raw IP / Linux SLL / null-loopback, IPv4 and IPv6, UDP and TCP. Anything it can't
parse is skipped rather than crashing. Checksums are ignored.
"""
from __future__ import annotations

import ipaddress
import os
import struct
from dataclasses import dataclass

# A capture is untrusted input read fully into memory. Cap it so a hostile or
# accidental multi-GB file can't exhaust memory. Generous default; overridable.
_MAX_PCAP_BYTES = int(os.environ.get("SBC_MAX_PCAP_BYTES", 512 * 1024 * 1024))

# link-layer header types (libpcap)
LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113
LINKTYPE_RAW_ALT = 12  # some captures use 12 for raw IP


@dataclass
class Packet:
    ts: float
    proto: str          # "udp" | "tcp"
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    payload: bytes


def _ip_str(b: bytes) -> str:
    return str(ipaddress.ip_address(b))


def _parse_ip(data: bytes):
    """Return (proto_num, src, dst, l4_bytes) or None."""
    if not data:
        return None
    version = data[0] >> 4
    if version == 4 and len(data) >= 20:
        ihl = (data[0] & 0x0F) * 4
        if len(data) < ihl:
            return None
        proto = data[9]
        src, dst = _ip_str(data[12:16]), _ip_str(data[16:20])
        return proto, src, dst, data[ihl:]
    if version == 6 and len(data) >= 40:
        proto = data[6]                       # next header (no ext-header walk)
        src, dst = _ip_str(data[8:24]), _ip_str(data[24:40])
        return proto, src, dst, data[40:]
    return None


def _parse_link(linktype: int, data: bytes) -> bytes | None:
    """Strip the link-layer header, return the IP packet bytes."""
    if linktype == LINKTYPE_ETHERNET:
        if len(data) < 14:
            return None
        etype = struct.unpack(">H", data[12:14])[0]
        off = 14
        while etype == 0x8100 and len(data) >= off + 4:   # VLAN tag(s)
            etype = struct.unpack(">H", data[off + 2:off + 4])[0]
            off += 4
        if etype in (0x0800, 0x86DD):
            return data[off:]
        return None
    if linktype in (LINKTYPE_RAW, LINKTYPE_RAW_ALT):
        return data
    if linktype == LINKTYPE_NULL:
        return data[4:] if len(data) >= 4 else None       # 4-byte address family
    if linktype == LINKTYPE_LINUX_SLL:
        return data[16:] if len(data) >= 16 else None
    return None


def read_packets(path: str) -> list[Packet]:
    size = os.path.getsize(path)
    if size > _MAX_PCAP_BYTES:
        raise ValueError(
            f"capture is {size} bytes, over the {_MAX_PCAP_BYTES}-byte limit "
            "(set SBC_MAX_PCAP_BYTES to raise it)"
        )
    with open(path, "rb") as fh:
        raw = fh.read()
    if len(raw) < 24:
        raise ValueError("not a pcap file (too short)")
    magic = raw[:4]
    if magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian, usec_div = ">", (1e6 if magic == b"\xa1\xb2\xc3\xd4" else 1e9)
    elif magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian, usec_div = "<", (1e6 if magic == b"\xd4\xc3\xb2\xa1" else 1e9)
    else:
        raise ValueError("unsupported pcap magic (pcapng is not supported)")

    linktype = struct.unpack(endian + "I", raw[20:24])[0]
    out: list[Packet] = []
    off = 24
    rec = struct.Struct(endian + "IIII")
    while off + 16 <= len(raw):
        ts_sec, ts_usec, incl, _orig = rec.unpack(raw[off:off + 16])
        off += 16
        if off + incl > len(raw):
            break
        frame = raw[off:off + incl]
        off += incl
        ip = _parse_link(linktype, frame)
        if ip is None:
            continue
        parsed = _parse_ip(ip)
        if parsed is None:
            continue
        proto, src, dst, l4 = parsed
        ts = ts_sec + ts_usec / usec_div
        if proto == 17 and len(l4) >= 8:                  # UDP
            sp, dp, ln = struct.unpack(">HHH", l4[:6])
            out.append(Packet(ts, "udp", src, dst, sp, dp, l4[8:8 + max(0, ln - 8)] or l4[8:]))
        elif proto == 6 and len(l4) >= 20:                # TCP
            sp, dp = struct.unpack(">HH", l4[:4])
            data_off = (l4[12] >> 4) * 4
            out.append(Packet(ts, "tcp", src, dst, sp, dp, l4[data_off:]))
    return out
