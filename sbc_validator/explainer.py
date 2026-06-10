"""
On-prem AI explanation layer for `explain` (opt-in via --ai).

Adds a plain-English failure-class explanation next to the deterministic pcap
diagnosis. Three hard rules, in line with the product discipline:

  1. RUNS IN THE AIR GAP. Pure stdlib, a small bundled naive-Bayes model over
     protocol-aware tokens. No network call, no cloud model, ever.
  2. NEVER THE VERDICT. The deterministic diagnoses (sip_trace) stay the verdict.
     If the model disagrees with the deterministic domain mapping, its output is
     suppressed and it says so. Silence beats a wrong verdict.
  3. NO RAW IDENTIFIERS. Tokenization normalizes every IP/FQDN/Call-ID to a typed
     placeholder before the model sees anything (same guarantee as report/anonymize).

The token scheme is PLUME-style protocol-aware tokenization adapted to SIP
(field-tree tokens, timing-gap buckets, normalized identifiers); design and the
training corpus generator live in research/2026-06-09-researchgravity-session/
artifacts/explainer-poc/. The bundled model is trained on the synthetic 6-class
corpus; it is a floor, retrained as real captures arrive (CONFIG-REQUEST).
"""
from __future__ import annotations

import ipaddress
import json
import math
import re
from pathlib import Path
from typing import Any, Iterable, Optional

_MODEL_PATH = Path(__file__).parent / "data" / "explainer_model.json"

_GAP_BUCKETS = [(0.5, "GAP:INSTANT"), (1.0, "GAP:FAST"), (30.0, "GAP:SLOW"),
                (180.0, "GAP:KEEPALIVE_WINDOW"), (float("inf"), "GAP:STALLED")]
_FQDN_RE = re.compile(r"\b([a-z0-9-]+\.)+[a-z]{2,}\b", re.I)

# failure class -> (validator domain, plain-English explanation, fix direction)
CLASS_INFO = {
    "CLEAN": ("ok", "Call signaling and media look healthy (two-way audio).", "None."),
    "REJECT_488": ("E", "The far end rejected the offered codecs (488): no overlap "
                   "between the SBC's SDP offer and what Teams accepts.",
                   "Align the codec list on the Teams leg (domain E)."),
    "ONE_WAY_AUDIO": ("D", "Media flows in one direction only; the SDP advertised a "
                      "private address, so return media cannot route.",
                      "Advertise the public media address / enable symmetric RTP (domain D)."),
    "TOPOLOGY_LEAK": ("F", "An internal/private address crossed the border in SIP "
                      "signaling headers (topology not hidden).",
                      "Enable topology hiding for Contact/Via/Record-Route (domain F)."),
    "OPTIONS_BLACKHOLE": ("B", "OPTIONS keep-alives were sent but never answered; Teams "
                          "marks the SBC down and silently stops routing to it.",
                          "Repair keep-alive/transport on the Teams leg (domain B)."),
    "TLS_HANDSHAKE_FAILED": ("C", "The TLS handshake was rejected with a fatal alert; "
                             "the call is cryptographically blocked before SIP starts "
                             "(the 2026 CA-migration failure mode).",
                             "Fix the trust store / certificate (domain C)."),
}


# ---------- tokenization (privacy layer included) ----------------------------------

def _norm_addr(addr: Optional[str]) -> str:
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
        base = re.split(r"[/ ]", c.strip())[0].upper()
        base = {"PCMU": "G711U", "PCMA": "G711A", "G711ULAW64K": "G711U",
                "G711ALAW64K": "G711A"}.get(base, base)
        out.append(f"CODEC:{base}")
    return out or ["CODEC:NONE"]


def tokenize_call(msgs: list[Any], *, tls_alert_code: Optional[int] = None,
                  rtp_oneway: Optional[bool] = None) -> list[str]:
    """Time-ordered SipMsg list (one call) -> normalized token stream.
    No raw IP/FQDN/Call-ID survives (the privacy gate; tested)."""
    toks: list[str] = ["<BOS>"]
    msgs = sorted(msgs, key=lambda m: m.ts)
    prev_ts = None
    for m in msgs:
        if prev_ts is not None:
            toks.append(_gap_token(m.ts - prev_ts))
        prev_ts = m.ts
        toks.append(f"DIR:{_norm_addr(m.src)}->{_norm_addr(m.dst)}")
        if m.method:
            toks.append(f"METHOD:{m.method.upper()}")
        if m.status:
            toks.append(f"STATUS:{m.status}")
        if m.media_ip is not None:
            toks.append(f"SDP:C={_norm_addr(m.media_ip)}")
            toks.extend(_codec_tokens(m.codecs))
            toks.append("SRTP:ON" if m.has_srtp else "SRTP:OFF")
        for hdr, _ip in (m.leaked or []):
            toks.append(f"TOPOLOGY_LEAK:{hdr.upper()}")
    if tls_alert_code is not None:
        toks.append(f"TLS_ALERT:{tls_alert_code}")
    if rtp_oneway is True:
        toks.append("RTP:ONEWAY")
    elif rtp_oneway is False:
        toks.append("RTP:TWOWAY")
    toks.append("<EOS>")
    return toks


# ---------- bundled naive-Bayes model ----------------------------------------------

class _Model:
    def __init__(self, class_tok: dict, class_n: dict, vocab_size: int):
        self.class_tok = class_tok
        self.class_n = class_n
        self.vocab_size = vocab_size

    @classmethod
    def load(cls, path: Path = _MODEL_PATH) -> "_Model":
        d = json.loads(path.read_text())
        return cls(d["class_tok"], d["class_n"], d["vocab_size"])

    def predict(self, tokens: list[str]) -> tuple[str, float]:
        """Return (class, confidence). Confidence = softmax over class log-probs."""
        total = sum(self.class_n.values())
        lps = {}
        for c, n in self.class_n.items():
            lp = math.log(n / total)
            counts = self.class_tok[c]
            denom = sum(counts.values()) + self.vocab_size
            for t in tokens:
                lp += math.log((counts.get(t, 0) + 1) / denom)
            lps[c] = lp
        best = max(lps, key=lps.get)
        m = lps[best]
        z = sum(math.exp(lp - m) for lp in lps.values())
        return best, 1.0 / z


def train_from_jsonl(corpus_path: str, out_path: str) -> dict:
    """Train the bundled model from a labeled corpus ({label, tokens} per line).
    Offline tool path; the verifier/explainer never trains at runtime."""
    class_tok: dict[str, dict[str, int]] = {}
    class_n: dict[str, int] = {}
    vocab = set()
    with open(corpus_path) as fh:
        for line in fh:
            r = json.loads(line)
            ct = class_tok.setdefault(r["label"], {})
            for t in r["tokens"]:
                ct[t] = ct.get(t, 0) + 1
                vocab.add(t)
            class_n[r["label"]] = class_n.get(r["label"], 0) + 1
    model = {"class_tok": class_tok, "class_n": class_n, "vocab_size": len(vocab)}
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    Path(out_path).write_text(json.dumps(model))
    return model


# ---------- the explain --ai entrypoint ---------------------------------------------

def explain_capture(path: str, det_result: dict) -> list[dict]:
    """AI explanation blocks for a capture, gated by the deterministic result.

    Returns one block per call (or one capture-level block when the capture has
    no SIP calls, e.g. a pure TLS-alert handshake failure). Each block:
      {scope, predicted_class, domain, confidence, explanation, fix,
       agrees_with_deterministic, suppressed, note?}
    """
    from .pcap import read_packets
    from .sip_trace import _is_sip, _parse_sip, _looks_rtp, _fatal_tls_alert, _MIN_RTP

    model = _Model.load()
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
        one_way = any((d, dp, s, sp) not in flows for (s, sp, d, dp) in flows)
    alerts = [c for c in (_fatal_tls_alert(p) for p in pkts) if c is not None]
    alert_code = alerts[0] if alerts else None

    # deterministic domains, the gate the model must agree with
    det_domains = {d["domain"] for d in det_result.get("top_diagnoses", [])}
    for c in det_result.get("calls", []):
        det_domains.update(d["domain"] for d in c.get("diagnoses", []))
    fault_domains = det_domains - {"ok"}

    calls: dict[str, list] = {}
    for m in msgs:
        calls.setdefault(m.call_id, []).append(m)

    def _block(scope: str, tokens: list[str]) -> dict:
        cls, conf = model.predict(tokens)
        domain, text, fix = CLASS_INFO[cls]
        agrees = (domain in fault_domains) if domain != "ok" else not fault_domains
        out = {"scope": scope, "predicted_class": cls, "domain": domain,
               "confidence": round(conf, 3), "explanation": text, "fix": fix,
               "agrees_with_deterministic": agrees, "suppressed": not agrees}
        if not agrees:
            out["note"] = ("AI suggestion suppressed: it does not match the "
                           "deterministic diagnosis, which stands. (Silence beats "
                           "a wrong verdict.)")
        return out

    blocks = []
    if calls:
        for cid, cmsgs in calls.items():
            blocks.append(_block(f"call {cid}",
                                 tokenize_call(cmsgs, tls_alert_code=alert_code,
                                               rtp_oneway=one_way)))
    elif alert_code is not None or pkts:
        blocks.append(_block("capture",
                             tokenize_call([], tls_alert_code=alert_code,
                                           rtp_oneway=one_way)))
    return blocks
