# SBC Domain Reference

Distilled domain knowledge for anyone working on this validator. Source:
*Session Border Controllers For Dummies, 7th Ribbon Special Edition* (Wiley,
2024) plus the Microsoft Direct Routing docs cited in [RULE_AUTHORITY.md]. This
is the canonical mental model of what an SBC does, mapped to what we validate.

Coverage legend: ✅ validated today · ◐ partial · ○ roadmap · — out of scope.

## What an SBC is

A Session Border Controller sits at the network border and controls real-time
communications (VoIP, video, UC) crossing it. It is a **B2BUA** (back-to-back
user agent): it terminates each call leg and re-originates the other, so it fully
mediates signaling and media and hides internal topology. Core jobs: security,
SIP interworking, media handling, and policy/routing.

## The canonical SBC functions (and our coverage)

| Function | What it means | Us |
|---|---|---|
| **Topology hiding (B2BUA)** | Hide internal IPs/architecture; never leak private addresses or internal headers to the far side | ✅ (private *media* IPs in D; signaling-plane leakage in Contact/Via/Record-Route/P-Asserted-Identity via domain F from a capture) |
| **Signaling encryption (TLS)** | mTLS on the SIP leg; cert chain, EKU, roots | ✅ (domain C) |
| **Media encryption (SRTP)** | `a=crypto` SRTP on the media leg; Teams requires `AES_CM_128_HMAC_SHA1_80` | ✅ (domain C `C.SRTP.DISABLED`, parsed for all four vendors; per-config cipher-suite match is roadmap) |
| **SIP normalization** | Translate SIP dialects/variants between vendors so calls interop | ◐ (we check normalization-profile *presence*, not behavior) |
| **Transcoding / transrating** | Convert codecs (and bitrates) on the fly; HD/wideband, low-bandwidth, fax/T.38 | ◐ (we check codec *overlap*; no transcode-capability or T.38 check) |
| **NAT traversal** | Prevent one-way audio: advertise a routable media address, symmetric RTP/latching | ✅ (domain D) |
| **Call admission control (CAC)** | Cap concurrent sessions; protect against overload and toll/TDoS abuse | ○ |
| **DDoS / TDoS protection** | Survive floods and rogue endpoints while admitting legitimate calls | — (runtime; monitor-mode roadmap) |
| **Access lists** | allow / block / grey lists of endpoints | ◐ (domain S on real AudioCodes AccessList: default-deny, broad CIDR, media-plane, IPv6 neglect; per-vendor extraction for Cisco/Ribbon/Oracle gated until a real config) |
| **Routing & classification** | Classify inbound traffic to an IP Group; route both directions Teams<->trunk | ✅ (domain G, when the source carries routing info) |
| **Routing & policy (advanced)** | Least-cost routing, dial plans, emergency/911, LNP, caller-name, screening | — (business policy, not our wedge) |
| **HA / resiliency** | No single point of failure; N:1 / N:M / active-active; session + media continuity on failover | ◐ (HA drift `diff` compares two nodes) |
| **SIPRec recording** | Fork signaling+media to a recorder without consuming switch ports | — |
| **Dual-stack / IPv4-IPv6 interworking** | Bridge IPv4 and IPv6 segments | — |

## SIP / media glossary (the terms that matter in findings)

- **B2BUA** — terminates and re-originates each leg; the basis of topology hiding
  and why the SBC can normalize/transcode at all.
- **SIP normalization** — IETF left SIP loosely specified, so vendor "dialects"
  differ. The SBC translates between them (static rules or on the fly). Missing
  normalization while bridging vendors breaks caller ID, diversion, and
  proprietary headers. (Our `B.SIP.NO_NORMALIZATION`.)
- **Transcoding vs transrating** — transcoding changes the codec; transrating
  changes the bitrate. Both are CPU/DSP-heavy. Needed when two legs share no
  codec, for HD/wideband (Teams/Zoom/Webex use wideband), and for
  bandwidth-constrained endpoints.
- **HD / wideband voice** — wideband codecs (e.g. SILK, G.722, Opus, AMR-WB)
  carry more frequency range than narrowband (G.711). Teams enables AMR-WB on DR
  trunks for non-bypass calls.
- **NAT traversal** — a private/non-routable IP advertised in SDP means remote
  RTP can't return, producing one-way audio (the #1 complaint). Symmetric
  RTP/latching is the fix. (Our domain D.)
- **Dynamic pinholing** — the SBC opens media ports only for the life of a
  session and closes them after, minimizing attack surface.
- **TLS + SRTP** — signaling secured by TLS, media by SRTP. Both are required for
  a secure Teams DR trunk.
- **CAC (call admission control)** — limits concurrent sessions; a QoS and
  anti-abuse control (also rate limiting, traffic policing).
- **SIPRec** — standard for replicating a call's signaling+media to a recorder;
  used for compliance and contact-center QA, and for lawful intercept.

## Use-case map

- **UC / enterprise** — first line of defense between the PBX/UCaaS and the
  carrier; HIPAA/PCI-DSS compliance pressure; 911 routing, CDRs, survivability.
- **Mobile / IMS** — VoLTE (4G) and VoNR (5G) ride IMS. SBC plays IMS roles:
  **P-CSCF + A-BGF** (entry point + media/NAT), **ATCF/ATGW** (handoff continuity),
  **I-BCF/I-BGF** (interconnect border, topology hiding, lawful intercept).
- **WebRTC** — browser real-time. Opus is WebRTC's default audio codec, VP8/H.264
  for video, so the SBC transcodes to G.711/G.729/H.264 for SIP/PSTN, and bridges
  RTP/SRTP and IPv4/IPv6. SIPRec for lawful intercept.
- **Contact center** — ultra-reliable; TDoS protection; SIPRec recording without
  extra ports; secure remote-agent connectivity without a VPN; internal-transfer
  routing that stays on the private network.

## Performance, scale, resiliency

- **Three-dimensional scaling** (Ribbon framing, but a useful model): signaling /
  general compute, media processing, and transcoding scale **independently**.
  Call-control scales by calls-per-second; transcoding by packets-per-second.
- **Capacity factors**: CPU headroom, concurrent sessions, registration rate,
  redundancy (N:1, N:M, active-active), QoS (policing, rate limiting, CAC).
- **Cloud-native SBC**: microservices + containers + Kubernetes lifecycle,
  elasticity/auto-scale, open APIs + telemetry (Prometheus/EFK), subscription
  network-wide licensing. (Matches our local-first container deployment story.)

## Threat model (mostly runtime; informs a future monitor mode)

Service theft / toll fraud, spoofing (caller ID), DDoS, **TDoS** (telephony DoS),
registration storms. These are detected/mitigated at runtime, not from static
config, so they belong to a clearly-separated active/monitor mode, not the
offline pre-deploy validator.

## Validator gaps this reference reveals (ranked, actionable)

Two gaps this reference originally flagged have since shipped:

- ✅ **Topology-hiding / private-IP leakage in signaling (domain F).** SHIPPED.
  `explain` flags RFC1918 addresses exposed in Contact/Via/Record-Route/
  P-Asserted-Identity from a capture (`F.TOPOLOGY_LEAK`).
- ✅ **SRTP media-encryption check (domain C).** SHIPPED. `C.SRTP.DISABLED`, with
  an `srtp_enabled` field parsed for all four vendors. Per-config cipher-suite
  matching against the ruleset allowlist remains roadmap.

Still open:

1. **Transcode-capability awareness (extend E).** When legs share no codec we
   flag it (and flag wideband-to-narrowband downgrade), but we do not yet read a
   transcode/DSP license flag (no overlap + no transcode = no audio).
2. **CAC / access-list posture (security hygiene).** Domain S now fires on real
   AudioCodes access lists; CAC (concurrent-session caps) and per-vendor ACL
   extraction for Cisco/Ribbon/Oracle remain a larger model lift.
3. **T.38 fax handling**, niche; only if a design partner needs it.

These are all offline-detectable from config (except the runtime threat model),
so they fit the local-first wedge. Topology-hiding (#1) is the recommended next
build: it is the most "obviously an SBC concern" to a 20-year vet and it deepens
the security story beyond the CA wedge.
