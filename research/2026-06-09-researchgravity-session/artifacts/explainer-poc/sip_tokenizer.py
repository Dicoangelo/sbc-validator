"""
Protocol-aware SIP tokenizer (POC) for the on-prem SBC-AutoOps call explainer.

Design (see ../../07-ONPREM-EXPLAINER-POC.md): adapt PLUME's recipe (arXiv 2603.13647)
to SIP. Three ideas:
  1. Split along the SIP/SDP field tree, not raw bytes -> short, high-information tokens.
  2. Emit GAP tokens for inter-message timing buckets -> the model can see a stalled
     OPTIONS keepalive (the CallTower blackhole) or a slow failover.
  3. Normalize every identifier (IP / FQDN / Call-ID / tag) to a typed placeholder. This
     makes the model learn call STRUCTURE instead of memorizing values, AND is the privacy
     layer: the token stream carries no raw locator, consistent with report/anonymize.py.

This runs on the EXISTING parsed event shape from sbc_validator/sip_trace.py:SipMsg
(ts, src, dst, first_line, method, status, call_id, cseq, codecs, media_ip, has_srtp,
leaked). It accepts either SipMsg objects or plain dicts with those keys. Pure stdlib.

It is deliberately NOT wired into the package yet (the parallel session owns sbc_validator/);
promote it deliberately. Run `python sip_tokenizer.py` for a self-test.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Iterable

# Timing buckets (seconds) -> gap token. Tuned to SIP realities: sub-second normal,
# 1-30s = slow, 30-180s = the OPTIONS-keepalive window, >180s = stalled/dead.
_GAP_BUCKETS = [(0.5, "GAP:INSTANT"), (1.0, "GAP:FAST"), (30.0, "GAP:SLOW"),
                (180.0, "GAP:KEEPALIVE_WINDOW"), (float("inf"), "GAP:STALLED")]

_FQDN_RE = re.compile(r"\b([a-z0-9-]+\.)+[a-z]{2,}\b", re.I)


def _norm_addr(addr: str | None) -> str:
    """An IP/host -> a typed placeholder. Privacy + structure in one step."""
    if not addr:
        return "<NONE>"
    host = addr.split(":", 1)[0].strip()
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            return "<IP-PRIVATE>"
        return "<IP-PUBLIC>"
    except ValueError:
        if _FQDN_RE.search(host):
            # Tag the Microsoft DR edge specifically: it is ground truth, not a leak.
            if "pstnhub.microsoft.com" in host.lower():
                return "<FQDN-MS-EDGE>"
            return "<FQDN>"
        return "<HOST>"


def _gap_token(dt: float) -> str:
    for hi, tok in _GAP_BUCKETS:
        if dt < hi:
            return tok
    return "GAP:STALLED"


def _codec_tokens(codecs: Iterable[str]) -> list[str]:
    out = []
    for c in codecs or []:
        # canonicalize (the M2 finding): upper, strip clock-rate, collapse aliases
        base = re.split(r"[/ ]", c.strip())[0].upper()
        base = {"PCMU": "G711U", "PCMA": "G711A", "G711ULAW64K": "G711U",
                "G711ALAW64K": "G711A"}.get(base, base)
        out.append(f"CODEC:{base}")
    return out or ["CODEC:NONE"]


def _get(msg: Any, key: str, default=None):
    if isinstance(msg, dict):
        return msg.get(key, default)
    return getattr(msg, key, default)


@dataclass
class TokenizedCall:
    call_id_placeholder: str          # always "<CID>" — never the real Call-ID
    tokens: list[str]

    def __str__(self) -> str:
        return " ".join(self.tokens)


def tokenize_call(msgs: list[Any], *, tls_alert_code: int | None = None,
                  rtp_oneway: bool | None = None) -> TokenizedCall:
    """A time-ordered list of SipMsg (one call) -> a normalized token stream.

    tls_alert_code / rtp_oneway come from sip_trace.analyze() (capture-level signals).
    """
    toks: list[str] = ["<BOS>"]
    msgs = sorted(msgs, key=lambda m: _get(m, "ts", 0.0))
    prev_ts = None
    for m in msgs:
        ts = _get(m, "ts", 0.0)
        if prev_ts is not None:
            toks.append(_gap_token(ts - prev_ts))
        prev_ts = ts

        toks.append(f"DIR:{_norm_addr(_get(m, 'src'))}->{_norm_addr(_get(m, 'dst'))}")
        method, status = _get(m, "method"), _get(m, "status")
        if method:
            toks.append(f"METHOD:{method.upper()}")
        if status:
            toks.append(f"STATUS:{status}")
        media_ip = _get(m, "media_ip")
        if media_ip is not None:
            toks.append(f"SDP:C={_norm_addr(media_ip)}")
            toks.extend(_codec_tokens(_get(m, "codecs", [])))
            toks.append("SRTP:ON" if _get(m, "has_srtp") else "SRTP:OFF")
        for hdr, _ip in (_get(m, "leaked", []) or []):
            toks.append(f"TOPOLOGY_LEAK:{hdr.upper()}")  # value normalized away
    if tls_alert_code is not None:
        toks.append(f"TLS_ALERT:{tls_alert_code}")
    if rtp_oneway is True:
        toks.append("RTP:ONEWAY")
    elif rtp_oneway is False:
        toks.append("RTP:TWOWAY")
    toks.append("<EOS>")
    return TokenizedCall("<CID>", toks)


def assert_no_raw_identifiers(tc: TokenizedCall, raw_values: Iterable[str]) -> None:
    """Privacy gate (mirrors report/anonymize.py): no raw locator may survive."""
    blob = str(tc)
    for v in raw_values:
        if v and v in blob:
            raise AssertionError(f"raw identifier leaked into token stream: {v!r}")


if __name__ == "__main__":
    # Self-test: a classic 488-codec-reject call with a private SDP IP and a leak.
    sample = [
        {"ts": 0.0, "src": "203.0.113.10:5061", "dst": "52.112.10.1:5061",
         "method": "INVITE", "status": None, "call_id": "abc123@sbc.contoso.com",
         "cseq": "1 INVITE", "codecs": ["PCMU/8000", "G729"],
         "media_ip": "10.1.2.3", "has_srtp": False,
         "leaked": [("Contact", "10.1.2.3")]},
        {"ts": 0.12, "src": "52.112.10.1:5061", "dst": "203.0.113.10:5061",
         "method": None, "status": "488", "call_id": "abc123@sbc.contoso.com",
         "cseq": "1 INVITE", "codecs": [], "media_ip": None, "has_srtp": False},
    ]
    tc = tokenize_call(sample, tls_alert_code=None, rtp_oneway=None)
    print(tc)
    # Prove the privacy guarantee holds on the raw values above.
    assert_no_raw_identifiers(tc, ["203.0.113.10", "52.112.10.1", "10.1.2.3",
                                   "abc123@sbc.contoso.com", "sbc.contoso.com"])
    print("\n[privacy] OK: no raw IP/FQDN/Call-ID survived tokenization.")
    assert "STATUS:488" in tc.tokens and "SDP:C=<IP-PRIVATE>" in tc.tokens
    assert "TOPOLOGY_LEAK:CONTACT" in tc.tokens and "<FQDN-MS-EDGE>" not in str(tc)
    print("[structure] OK: 488 reject, private SDP IP, Contact topology-leak all tokenized.")
