---
title: "SBC Validator: One Page"
---

# SBC Validator

**The independent truth layer for real-time voice.** A local-first, vendor-agnostic
tool that validates Session Border Controller configs *before* deployment,
predicts how a call would fail, and explains failures from a packet capture. Runs
inside the customer's environment, air-gapped. Raw configs never leave.

## The wedge: the 2026 Microsoft CA migration

Every SBC's trust store must carry the current Microsoft root set or Teams calls
hard-stop at the TLS handshake. Enterprises run 50+ mixed-vendor SBCs with no
cross-vendor, pre-deployment tool. Everything that exists is single-vendor (Cisco
DNA, AudioCodes OVOC, Ribbon LEAP) or post-deployment (AIOps watching MOS/jitter).
We are the only multi-vendor, pre-deployment layer. "LEAP, but cross-vendor."

## What runs today (8 validation domains x 4 vendors, one model)

| | Domain | Catches |
|---|---|---|
| A | Syntax/semantic | malformed / inconsistent config |
| B | Interop | TLS transport, OPTIONS keep-alive, normalization, IP-as-identity |
| C | TLS / CA (the wedge) | root CAs, EKU, expiry, trust-anchor chain, SRTP, wildcard certs |
| D | NAT / media | one-way audio (private SDP IP, no symmetric RTP) |
| E | Codec | Teams overlap, transcode / DSP, wideband downgrade |
| F | Topology | private-IP leakage on the signaling plane (from pcap) |
| G | Routing | classification + both-direction routes |
| S | Security | default-deny, broad CIDR, media-plane ACL, IPv6 neglect |

Vendors: **AudioCodes, Cisco CUBE, Ribbon, Oracle Acme** on one normalized model.
Three modes: **validate** (static), **simulate** (predict the call), **explain**
(pcap post-mortem). Plus HA-drift `diff`, fleet readiness, a CI/CD gate, a local
dashboard, and an executive report.

## Proven vs. honest gaps

- **Proven:** 4 vendors, 8 domains, signed authority-sourced rules, 79 tests in CI,
  air-gapped Docker image, clean-install acceptance (16/16).
- **Gated (zero false positives until real configs):** routing + security for
  Cisco/Ribbon/Oracle, per-config cipher matching, live probing. The tool stays
  silent rather than guess wrong, that discipline *is* the moat.

## The ask

One real (sanitized) SBC config per vendor. It turns routing + security real for
that vendor, the same path that made AudioCodes real. See CONFIG-REQUEST.md.

*Metaventions AI. Philip Drammeh (telecom domain) and Dico Angelo (AI builder).
Contact: dicoangelo@metaventionsai.com*
