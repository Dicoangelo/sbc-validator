"""
Predicted call-flow simulation (offline, deterministic).

A real call is a chain of links: TLS handshake -> SIP signaling -> SDP
offer/answer -> media path. It dies at the first broken link, and an engineer
diagnoses it by knowing which symptom maps to which link. This module models that
chain from static config + the validator findings, predicts how far a call would
get, names the user-visible symptom, and renders the SIP ladder up to the failure.

It originates no traffic. Everything here is inference from the normalized config
and the rule bundle, so it stays inside the local-first trust boundary. Outcomes
are labeled "predicted", never "tested live".
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .models import NormalizedConfig
from .validators.base import Finding, Severity

# Which findings break which stage of the call, and whether they hard-stop it.
# A hard-stop means the call never reaches the next stage.
_TLS_HARDSTOP = {
    "C.CA.ROOT_MISSING", "C.TLS.NO_CONTEXT", "C.TLS.MTLS_DISABLED",
    "C.CERT.MISSING", "C.CERT.FQDN_MISMATCH",
    # A leaf Teams will not trust hard-stops the handshake just like a missing root:
    # self-signed, a chain that fails signature verification, or a chain that
    # terminates at a root outside the required Microsoft/DigiCert set.
    "C.CERT.SELF_SIGNED", "C.CERT.CHAIN_INVALID", "C.CERT.UNTRUSTED_ANCHOR",
    # No cipher in common with Direct Routing means the negotiation produces no
    # shared suite: the handshake hard-fails before any cert is exchanged.
    "C.TLS.CIPHER_NOT_ALLOWED",
}
# C.CERT.EXPIRY is handled severity-aware below: CRITICAL (already expired) hard-
# stops the handshake; MEDIUM (expiring soon) is a warning. Same id, two outcomes.
# C.TLS.WEAK_VERSION is a WARN, not a hard-stop: a low TLS *floor* is downgrade
# exposure, but the handshake can still negotiate 1.2+ if the SBC offers it, so
# treating it as a guaranteed NO_CONNECT would be its own over-guess.
_TLS_WARN = {"C.CERT.EKU_NO_SERVERAUTH", "C.CERT.CHAIN_INCOMPLETE", "C.CERT.EKU_DUALUSE",
             "C.TLS.WEAK_VERSION"}
_SIP_HARDSTOP = {
    "B.SIP.TRANSPORT", "B.IFACE.NO_TEAMS", "A.STRUCT.NO_SIP_INTERFACES",
    "A.SEM.DANGLING_TLS",
    # Teams requires an FQDN identity; an IP in the SIP identity draws a 403.
    "B.SIP.IDENTITY_IS_IP",
    # routing/classification faults: the call never sets up (404 / rejected)
    "G.CLASS.UNCLASSIFIED", "G.ROUTE.NO_FROM_TEAMS", "G.ROUTE.NO_TO_TEAMS",
}
_SIP_WARN = {"B.SIP.OPTIONS_KEEPALIVE", "B.SIP.NO_NORMALIZATION"}
_SDP_HARDSTOP = {"E.CODEC.NO_TEAMS_OVERLAP", "E.CODEC.NONE_OFFERED"}
_SDP_WARN = {"E.CODEC.NO_CROSS_OVERLAP", "E.DTMF.METHOD", "E.DTMF.INCONSISTENT"}
_MEDIA_HARDSTOP = {"D.NAT.PRIVATE_ADVERTISED", "D.NAT.NO_PUBLIC_IP", "C.SRTP.DISABLED"}
_MEDIA_WARN = {"D.NAT.NO_SYMMETRIC_RTP", "D.MEDIA.NO_REALM"}


@dataclass
class CallStage:
    name: str
    status: str                       # "ok" | "warn" | "fail"
    detail: str
    symptom: str = ""                 # user-visible complaint when not ok
    driven_by: list[str] = field(default_factory=list)


@dataclass
class CallSimulation:
    outcome: str                      # STABLE | NO_CONNECT | REJECTED | ONE_WAY_AUDIO | NO_MEDIA | DEGRADED
    dies_at: Optional[str]
    summary: str
    negotiated_codec: Optional[str]
    transcode_required: bool
    stages: list[CallStage]
    ladder: list[str]


def _by_stage(findings, ids):
    return [f for f in findings if f.check_id in ids]


def _negotiate(config: NormalizedConfig, ruleset: dict):
    """Return (negotiated_codec_on_teams_leg, transcode_required, teams_offered)."""
    teams = config.teams_interface()
    supported = ruleset.get("E", {}).get("teams_supported_codecs", [])
    teams_offered = (teams.offered_codecs or []) if teams else []
    negotiated = next((c for c in teams_offered if c in supported), None)
    legs = [i.offered_codecs for i in config.sip_interfaces if i.offered_codecs]
    transcode = False
    if len(legs) >= 2:
        common = set(legs[0])
        for leg in legs[1:]:
            common &= set(leg)
        transcode = not common
    return negotiated, transcode, teams_offered


def simulate_call(config: NormalizedConfig, ruleset: dict,
                  findings: list[Finding]) -> CallSimulation:
    teams = config.teams_interface()
    negotiated, transcode, teams_offered = _negotiate(config, ruleset)

    stages: list[CallStage] = []
    dies_at = None
    outcome = "STABLE"

    def ids_of(fs):
        return [f.check_id for f in fs]

    # ---- Stage 1: TLS handshake ----
    # An already-expired cert (C.CERT.EXPIRY at CRITICAL) hard-stops the handshake;
    # the same id at MEDIUM (expiring soon) is only a warning.
    expired_now = [f for f in findings
                   if f.check_id == "C.CERT.EXPIRY" and f.severity == Severity.CRITICAL]
    expiring_soon = [f for f in findings
                     if f.check_id == "C.CERT.EXPIRY" and f.severity != Severity.CRITICAL]
    tls_fail = _by_stage(findings, _TLS_HARDSTOP) + expired_now
    tls_warn = _by_stage(findings, _TLS_WARN) + expiring_soon
    if tls_fail:
        stages.append(CallStage(
            "TLS handshake", "fail",
            "mTLS to the Teams SIP proxy cannot complete: " +
            "; ".join(f.title for f in tls_fail),
            symptom="SBC never registers with Teams. Get-CsOnlinePSTNGateway shows "
                    "it inactive, SIP OPTIONS go unanswered, and NO calls connect "
                    "in either direction.",
            driven_by=ids_of(tls_fail)))
        dies_at, outcome = "TLS handshake", "NO_CONNECT"
    else:
        s = "warn" if tls_warn else "ok"
        detail = "mTLS handshake completes; SBC cert trusted by Teams."
        sym = ""
        if tls_warn:
            detail = "Handshake completes today, but at risk: " + \
                     "; ".join(f.title for f in tls_warn)
            sym = ("As of the June 2026 serverAuth-EKU enforcement, this cert may "
                   "lose trust and the handshake can start hard-failing.")
        stages.append(CallStage("TLS handshake", s, detail, sym, ids_of(tls_warn)))

    # ---- Stage 2: SIP signaling ----
    if dies_at is None:
        sip_fail = _by_stage(findings, _SIP_HARDSTOP)
        sip_warn = _by_stage(findings, _SIP_WARN)
        if sip_fail:
            stages.append(CallStage(
                "SIP signaling", "fail",
                "Teams rejects SIP signaling: " + "; ".join(f.title for f in sip_fail),
                symptom="TLS is fine but Teams will not exchange SIP. OPTIONS are "
                        "rejected, the SBC is marked down, and calls fail to set up.",
                driven_by=ids_of(sip_fail)))
            dies_at, outcome = "SIP signaling", "NO_CONNECT"
        else:
            s = "warn" if sip_warn else "ok"
            detail = "SIP OPTIONS answered; signaling channel healthy."
            sym = ""
            if sip_warn:
                detail = "Signaling works but is fragile: " + \
                         "; ".join(f.title for f in sip_warn)
                sym = ("Intermittent: the SBC can be marked unhealthy and calls "
                       "fail sporadically; header gaps can break caller ID.")
            stages.append(CallStage("SIP signaling", s, detail, sym, ids_of(sip_warn)))

    # ---- Stage 3: SDP offer/answer ----
    if dies_at is None:
        sdp_fail = _by_stage(findings, _SDP_HARDSTOP)
        sdp_warn = _by_stage(findings, _SDP_WARN)
        if sdp_fail:
            stages.append(CallStage(
                "SDP negotiation", "fail",
                f"No common codec on the Teams leg (offered {teams_offered or '[]'}); "
                "the INVITE is rejected.",
                symptom="Call is rejected the instant it is placed: caller hears fast "
                        "busy or 'your call cannot be completed' (SIP 488).",
                driven_by=ids_of(sdp_fail)))
            dies_at, outcome = "SDP negotiation", "REJECTED"
        else:
            s = "warn" if sdp_warn else "ok"
            detail = (f"Codecs negotiate to {negotiated} on the Teams leg."
                      if negotiated else "Codecs negotiate.")
            sym = ""
            if transcode:
                detail += " Legs share no codec, so the SBC must transcode."
            if sdp_warn:
                sym = ("If transcoding is not licensed/enabled there will be no audio; "
                       "mismatched DTMF means IVR keypresses do nothing.")
            stages.append(CallStage("SDP negotiation", s, detail, sym, ids_of(sdp_warn)))

    # ---- Stage 4: Media path ----
    if dies_at is None:
        media_fail = _by_stage(findings, _MEDIA_HARDSTOP)
        media_warn = _by_stage(findings, _MEDIA_WARN)
        if media_fail:
            srtp = any(f.check_id == "C.SRTP.DISABLED" for f in media_fail)
            stages.append(CallStage(
                "Media path", "fail",
                "Media cannot establish: " + "; ".join(f.title for f in media_fail),
                symptom=("Call signals through but media never encrypts; Teams drops "
                         "the media and there is no audio."
                         if srtp else
                         "Call connects and rings, but audio is one-way (or silent). "
                         "RTP from Teams never returns, and the call typically drops "
                         "~30s after answer."),
                driven_by=ids_of(media_fail)))
            dies_at, outcome = "Media path", ("NO_MEDIA" if srtp else "ONE_WAY_AUDIO")
        else:
            s = "warn" if media_warn else "ok"
            detail = "Media address is routable; RTP can flow both ways."
            sym = ""
            if media_warn:
                detail = "Media reachable but latching disabled."
                sym = "Media from NATed peers may be dropped, causing one-way audio."
            stages.append(CallStage("Media path", s, detail, sym, ids_of(media_warn)))

    # Outcome refinement: clean chain with warnings = DEGRADED, not STABLE.
    if dies_at is None and any(st.status == "warn" for st in stages):
        outcome = "DEGRADED"

    summary = _summarize(outcome, dies_at, negotiated)
    ladder = _ladder(config, ruleset, stages, dies_at, negotiated, teams_offered, transcode)
    return CallSimulation(outcome, dies_at, summary, negotiated, transcode, stages, ladder)


def _summarize(outcome, dies_at, codec):
    return {
        "STABLE": f"Predicted: call connects with two-way audio"
                  + (f" using {codec}." if codec else "."),
        "DEGRADED": "Predicted: call can connect but is degraded/at-risk (see warnings).",
        "NO_CONNECT": f"Predicted: NO calls connect. Chain breaks at {dies_at}.",
        "REJECTED": "Predicted: calls are rejected immediately (SIP 488) at SDP negotiation.",
        "ONE_WAY_AUDIO": "Predicted: call connects but audio is one-way and drops ~30s in.",
        "NO_MEDIA": "Predicted: call signals through but media never encrypts; Teams "
                    "drops the media and there is no audio.",
    }.get(outcome, "Predicted: see stages.")


def _ladder(config, ruleset, stages, dies_at, codec, teams_offered, transcode):
    """ASCII SIP ladder for the predicted flow, truncated at the failure point."""
    L = "SBC".ljust(8)
    R = "Microsoft Teams SIP proxy"
    out = [f"{L}{R}", f"{'':8}{'-'*len(R)}"]

    def msg(arrow, text):
        out.append(f"{'':8}{arrow} {text}")

    status = {s.name: s.status for s in stages}

    # TLS
    msg("  -->", "TLS ClientHello")
    if status.get("TLS handshake") == "fail":
        msg("  <--", "TLS alert: unknown CA / handshake failed   << call dies here")
        return out
    msg("  <--", "TLS handshake OK" + (" (cert at risk post-2026-06)"
                                       if status.get("TLS handshake") == "warn" else ""))
    # SIP OPTIONS
    msg("  -->", "OPTIONS (keep-alive)")
    if status.get("SIP signaling") == "fail":
        msg("  <--", "403 / no response: SBC marked down   << call dies here")
        return out
    msg("  <--", "200 OK")
    # INVITE / SDP
    offer = ",".join(teams_offered) if teams_offered else "(none)"
    msg("  -->", f"INVITE  SDP offer: {offer}")
    if status.get("SDP negotiation") == "fail":
        msg("  <--", "488 Not Acceptable Here: no common codec   << call dies here")
        return out
    msg("  <--", "100 Trying")
    msg("  <--", "180 Ringing")
    ans = codec or "negotiated"
    msg("  <--", f"200 OK   SDP answer: {ans}")
    msg("  -->", "ACK")
    # Media
    if status.get("Media path") == "fail":
        media_stage = next((s for s in stages if s.name == "Media path"), None)
        srtp = bool(media_stage and "C.SRTP.DISABLED" in media_stage.driven_by)
        if srtp:
            out.append(f"{'':8}   x   media offered without SRTP (a=crypto absent)")
            out.append(f"{'':8}      Teams drops the media; no audio in either direction")
        else:
            out.append(f"{'':8}   x   RTP offered to a private/unreachable address")
            out.append(f"{'':8}      one-way audio; remote RTP never returns; drops ~30s")
        return out
    note = " (SBC transcoding)" if transcode else ""
    out.append(f"{'':8} ===  RTP {ans} bidirectional{note}  ===")
    return out
