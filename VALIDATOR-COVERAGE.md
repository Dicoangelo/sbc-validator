# Validator Coverage vs. the Canonical SBC Failure Modes

Maps the SBC misconfiguration failure-mode taxonomy (from the research corpus:
vendor hardening guides + the whitespace analysis, via the NotebookLM source set)
to what the validator actually checks. Updated 2026-06-08.

Legend: ✅ covered · 🟡 partial · ⛔ gap (backlog)

## The B2BUA is two-legged

An SBC terminates the external (Teams) session and creates a new internal
(carrier/PBX) session, translating between them. A validator that only inspects
the Teams leg is blind to half the device. Current per-leg coverage:

| Concern | Teams leg | Carrier leg |
|---|---|---|
| Transport = TLS | ✅ B.SIP.TRANSPORT | (carrier is often UDP/TCP by design) |
| OPTIONS keep-alive | ✅ B.SIP.OPTIONS_KEEPALIVE | ✅ B.SIP.CARRIER_NO_KEEPALIVE (advisory) |
| Cert / EKU / chain / roots | ✅ domain C | 🟡 carrier TLS posture not inspected |
| SRTP / media security | ✅ C.SRTP | 🟡 SRTP↔RTP interworking not modeled |
| Codec set | ✅ E (Teams overlap) | ✅ E (cross-leg overlap) |
| Transcode / DSP load | ✅ E.CODEC.NO_CROSS_OVERLAP + WIDEBAND_DOWNGRADE | (same) |
| Access-control posture | n/a | 🟡 domain S built, needs per-vendor ACL extraction |

## Failure-mode taxonomy → checks

**TLS / certificate / CA**
- Trust-chain disconnection on CA migration → ✅ C trust-anchor chain
- FQDN vs CN/SAN mismatch → ✅ C.CERT.CN_SAN
- Cipher-suite / mTLS mismatch → 🟡 ciphers encoded in ruleset, not yet asserted per-config

**SIP header / normalization**
- Regex rewrite typo (Contact header) → ⛔ cannot statically validate regex *correctness*; we check normalization *presence* (B.SIP.NO_NORMALIZATION). Realistic ceiling for static analysis.
- Config-wizard overwrite → ⛔ process issue, not a config-state check

**NAT / media / SDP**
- Private IP advertised in SDP → ✅ D.NAT.PRIVATE_ADVERTISED
- Missing symmetric RTP → ✅ D.NAT.NO_SYMMETRIC_RTP
- Media-plane ACL omission (signaling allowed, RTP subnet not) → 🟡 **S.ACL.MEDIA_PLANE_MISSING** (needs ACL extraction)

**Codec / transcoding**
- Transcoding / DSP exhaustion → ✅ E.CODEC.NO_CROSS_OVERLAP (now names DSP cost) + E.CODEC.WIDEBAND_DOWNGRADE

**Routing / dial-plan / classification**
- Missing route direction / unclassified Teams → ✅ domain G (AudioCodes today)
- Routing on Cisco/Ribbon/Oracle → ⛔ parsers don't yet extract routes (G silent for them)
- Overly broad CIDR permit → 🟡 **S.ACL.BROAD_CIDR**
- Top-down rule shadowing → ⛔ needs ordered-ACL model

**HA / failover**
- OPTIONS keep-alive busyout → ✅ B (both legs now)
- Trust-store drift on failover → ✅ `diff` (HA.DRIFT.TRUST_STORE)

**Security / DoS** (new domain S, fires when the source carries ACL info)
- Missing default-deny → 🟡 S.ACL.NO_DEFAULT_DENY
- IPv6 plane neglect (default-allow bypass) → 🟡 S.ACL.IPV6_NEGLECT
- SIP unknown-peer IPACL exposure → 🟡 S.ACL.NO_DEFAULT_DENY (same posture)
- RTP source-address validation disabled → 🟡 S.RTP.SOURCE_VALIDATION_OFF

## What "🟡 domain S" means

The domain-S validator and its logic are implemented and unit-tested, but it
stays **silent until a parser populates `access_controls` / `rtp_source_validation`**
from a real config (same "absent vs. not-in-this-source" discipline as routing and
the trust store). Lighting it up on real configs is per-vendor extraction work:
AudioCodes Firewall / IP Access List, Oracle access-control / ACLI, Cisco/Ribbon ACLs.

## Prioritized backlog (grounded in the corpus)

1. **ACL extraction per vendor** → turns domain S from "ready" to "firing" on real
   configs. Highest security value; the corpus treats ACL posture as first-class.
2. **Routing extraction for Cisco / Ribbon / Oracle** → domain G currently only
   engages for AudioCodes.
3. **Cipher-suite / mTLS assertion** (domain C) → ciphers are in the ruleset; assert
   the config's TLS context offers an approved suite and mTLS is on.
4. **SRTP↔RTP interworking awareness** → external SRTP + internal RTP is normal, but
   flag Teams-leg-without-SRTP and inconsistent media-security across legs.
5. **Exact MS Direct Routing protocol values** (cipher list, ports, OPTIONS interval)
   are NOT in the corpus — pull from Microsoft Learn (Firecrawl) to harden the ruleset.
