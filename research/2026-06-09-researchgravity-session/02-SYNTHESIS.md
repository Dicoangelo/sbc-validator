# SBC-AutoOps — ResearchGravity Synthesis

**Format:** Thesis -> Gap -> Innovation Direction (ResearchGravity standard)
**Date:** 2026-06-09 | **Build:** v0.16.1, 126 tests | **Status:** design-partner stage

---

## THESIS

**SBC-AutoOps is the independent truth layer for real-time voice: a local-first,
vendor-agnostic validator that checks a Session Border Controller config before it
ships, predicts how a call would fail, and explains failures from a packet capture.**

It is the only multi-vendor, pre-deployment, Layer-5 validation layer in a market
where every incumbent tool is either single-vendor (Cisco DNA, AudioCodes OVOC, Ribbon
LEAP) or post-deployment (AIOps watching MOS/jitter after the call already dropped).
The positioning that holds this together, settled 2026-05-27 and never to be relitigated:
**we do not build an SBC; we build the external diagnostic that plugs into the SBCs the
customer already owns. The vendors are our channel, not our competitors. "Ribbon LEAP,
but cross-vendor, before you hit commit."**

Three structural facts make the thesis defensible rather than aspirational:

1. **The blind spot is real and architectural.** An SBC is a Back-to-Back User Agent: it
   terminates the external session and creates a new internal one. NetDevOps automation
   (Terraform, Ansible) validates Layer 3/4 flawlessly and is completely blind to the
   Layer-5 SIP/SDP state machine. A mismatched SDP profile connects the call and destroys
   the audio; a one-character header-rewrite typo kills a trunk silently. Generic tooling
   structurally cannot reason about this.

2. **The product genuinely runs, and it is honest.** 4 real vendor parsers (AudioCodes
   `.ini`, Cisco CUBE IOS-XE, Ribbon `set`-config, Oracle/Acme ACLI) emit ONE normalized
   model; 8 deterministic validators (A syntax, B interop, C TLS/CA wedge, D NAT, E codec,
   F topology-leak, G routing, S security) run unmodified across all four. The discipline
   that is the moat: **when the source does not carry the information to judge something,
   the validator stays silent rather than guess.** A wrong "fix this" verdict is the one
   thing the product cannot afford, and the codebase enforces that (gated G/S for the three
   vendors not yet hardened; wildcard-aware cert matching; tristate "unknown vs absent").

3. **The ruleset is authoritatively correct.** Reconciled 2026-06-09 against the live
   Microsoft Learn Direct Routing doc tree: the 7 required roots + SHA-1 thumbprints, the
   forced TLS 1.2, the exact 4 cipher suites, the SRTP suite, and the test endpoint all
   EXACT-match Microsoft's own source of truth. The validator is not inferring Microsoft's
   posture; it is encoding it, signed (Ed25519) and version-stamped.

---

## GAP

The gaps are well-understood by the team and documented candidly (REVIEW-FINDINGS,
RECURSIVE_IMPROVEMENT). The RG lens sorts them into three that actually bind the
outcome, separated from the long tail of correctness debt.

### Gap 1 — The wedge is a calendar, and the calendar is almost spent
The entire go-to-market urgency rode the Microsoft 2026 CA migration. But the hard
root-CA cutoff (Mar 31) has passed, the April server rollout is done, and the
serverAuth-EKU change is "Effective June 2026" with no specific day. A deadline
narrative is a campaign; **it dies at the deadline.** After it, a survivor reads the
pitch as "our calls work, we made it, we do not need this." This is the single biggest
threat to the business and it is a *narrative/positioning* failure, not a product one.

### Gap 2 — The only durable moat is an IOU
The cross-vendor normalized model is real but LLMs collapsed parser cost to a 6-12 month
asset; a funded competitor can replicate it. The durable moat is the
**observability-semantics matrix** (what a *missing* config line means, per vendor, per
firmware), and it can only be built from real production configs. Today that count is
**~1** (only AudioCodes is hardened against a real Mediant `.ini`; C7 in REVIEW-FINDINGS
is the standing admission). Worse, the air-gap trust model **self-cancels the data moat**:
"raw configs never leave" is the security wedge AND the reason the corpus stays thin. The
contradiction is live on the marketing page (hero "raw configs never leave" vs. moat
"compounding data corpus") and is only half-reconciled.

### Gap 3 — The beachhead ICP is deferred, and runway is finite
The product is built enterprise-shaped (VPC-bound, fleet rollup), but enterprise
procurement cycles can outlast the runway the June wedge bought. The BYOC-SMB segment is
fast/desperate but low-volume and low-value. The fork has been *deferred*, not *decided*,
and deferral is itself the risk: parser fidelity (Gap 2) depends on design-partner configs,
so a stalled GTM stalls the build.

### Secondary (correctness debt, already triaged, not outcome-binding)
- Deterministic ceiling: static analysis can verify a normalization profile is present,
  never that an arbitrary SIP-header regex is correct. Honest boundary, state it.
- Carrier-leg under-validation (skewed to the Teams leg); SRTP-to-RTP interworking unmodeled.
- One live bug flagged but possibly not fully shipped: H4 score-gate (16 MEDIUMs printing
  "Risk 96, Verdict PASS"). Verify it landed before any expert review. (Insight 00 says
  commit 3ecd00a shipped it; confirm against `report/risk.py`.)
- Doc drift on the headline metric: README/REVIEW-FINDINGS say 100 tests, Philip packet
  says 104, the repo is at **126**. Cheap credibility leak; sweep before the meeting.

---

## INNOVATION DIRECTION

Five moves, ordered by leverage. The first three are *already identified and partly
executed in the repo's own `marketing/insights/`* — this synthesis ratifies them and
sharpens the sequencing. The last two are the longer-horizon frontier from the vault.

### Direction 1 (do first) — Re-anchor the category: "cryptographic change management for real-time voice"
Convert the one-time 2026 deadline into the first episode of a permanent regime. The
durable, third-party-verifiable cadence:
- **CA/Browser Forum cert-lifetime compression**: 398 -> 200 days (Mar 2026) -> 100 (Mar 2027)
  -> 47 (by Mar 2029). DR SBC certs ARE public-CA certs, so this hits every fleet, forever.
- **Scheduled PQC migration** (NIST ML-KEM/ML-DSA finalized Aug 2024; Cloudflare ~38% hybrid
  HTTPS by Mar 2025; SIP is asleep on this).
- **Continuous Chrome Root Program tightening.**

"Trust now rotates faster than telecom; this is the layer that keeps them in sync." This
dissolves the survivor objection, makes per-SBC subscription pricing coherent, and reframes
the engine correctly: **the signed rule feed IS the business** (the antivirus-definitions
model). Each enforcement wave is a new signed bundle on the same deterministic engine. The
freshness-floor + rollback-refusal already in the code is, structurally, a
subscription-enforcement layer.

### Direction 2 (do second) — Sell through the consultancy channel
The fastest converter is NOT BYOC-SMB or enterprise-direct; it is the **consultancies
already paid to do Microsoft MC1235747 remediation with no multi-vendor tool**: eGroup /
Enabling Technologies, Server Consultancy (UK), ChangePilot. A small white-label license:
- closes on **one PO with no enterprise security review**,
- pulls **real end-customer configs in** (directly closing Gap 2 and the C7 parser gap that
  silences G/S on 75% of vendors),
- and **multiplies reach** through their existing engagements.

It is the single fastest path to BOTH revenue and the moat data. Lighthouse named target:
**TP ICAP** (AudioCodes + Cisco CUBE, MiFID II) — the June serverAuth-EKU change points
straight at Cisco CUBE estates. Pair with **post-incident selling** to the fresh-scar
accounts (Voipcloud, CallTower) over preparedness selling, with the precise caveat that
FusionConnect's failure was Microsoft-media-relay-side and not catchable from a customer
config.

### Direction 3 (do third) — Ship the free outside-in scanner as the moat bootstrap
"SSL Labs for SBCs": enter your SBC FQDN, we run a real TLS handshake against it AND against
Microsoft's published edge (`sip.g1.pstnhub.microsoft.com:5061`, already in the signed
ruleset and Microsoft-sanctioned), return a graded readiness card. **Outside-in is the whole
point**: no config upload, so it never contradicts the trust thesis on the landing page. It
delivers four returns on one build: zero-friction lead-gen (a shareable grade is its own
distribution), arms the consultancy channel as a triage front-end, **bootstraps an
anonymized benchmark corpus without touching configs** (the answer to Gap 2's
self-cancellation), and flips the product's weakest verb from "predicted" to "verified
against Microsoft's own 2026 infrastructure." The `probe` CLI engine is already built (126
tests). The remaining work is the thin stateless web front-end on the same zero-external-
request discipline as the marketing page. **And: "install a control"** — get a regulated
partner (MiFID II / FINRA / CJIS) to name SBC-AutoOps as the mandated pre-deploy step in
their audited change-management procedure. Controls do not churn.

### Direction 4 (frontier, fast-follow) — The LLM-on-PCAP explainer as the flagship IP
The vault's highest patent-claim-to-prior-art ratio: an LLM fine-tuned to read SIP from a
PCAP captured at the SBC's signaling port and emit a ladder + plain-English root cause
(prior art LLMcap is network-generic). This is the one place AI belongs in the product, and
it is explicitly NOT in the verdict path (determinism stays sacred; AI is the explanation
layer). It deepens the `explain` mode that already ships and is the natural Phase-2 wedge
once configs are flowing.

### Direction 5 (frontier, optionality) — The greenfield sidecars
Held as optionality, not roadmap commitments, but each is genuine whitespace:
- **Deepfake-voice detection as a SIPREC/media-fork sidecar that taps SBC media** (Pindrop
  +1,300% deepfake surge 2024; zero vendor incumbent at the SBC layer). License path, not build.
- **PQC migration readiness scoring for SIPS/SRTP** (whitepaper owns the category narrative).
- **Out-of-band STIR/SHAKEN + RCD conformance auditing** (FCC 8th R&O Sept 2025, RFC
  9795/9796 RCD July 2025) — same buyer as Teams DR readiness, adjacent compliance surface.

---

## THE SINGLE BINDING CONSTRAINT (unchanged since 2026-05-27)

**One real, sanitized SBC config per vendor** (CONFIG-REQUEST). It simultaneously:
- closes the parser-fidelity gap (C7) and lights up routing (G) + security (S) for
  Cisco/Ribbon/Oracle,
- seeds the only durable moat (the observability-semantics matrix),
- and is unblocked by Direction 2 (the consultancy channel brings configs as a side effect
  of the engagement).

Everything else is sequencing around this one unlock. The team already knows it. The job is
to make the channel that produces it the center of the GTM, not a footnote in the ask.

---

## RG corroboration (innovation frontier, from the corpus)
- Deepfake at the SBC layer: greenfield (Pindrop 2025: +1,300% surge, $44.5B projected 2025
  exposure; ASVspoof 2024 + SpoofCeleb 2025 are first datasets).
- PQC-TLS-for-SIP gap: Cloudflare 38% hybrid HTTPS Mar 2025; NIST finalized Aug 2024; SIP
  asleep.
- SBC IaC + fuzzing vacuum: no Terraform providers for AudioCodes Mediant / Ribbon CNe /
  Oracle CN-SBC; sippts removed its fuzzer in v4.0 (vacated slot).
- Patent whitespace (Nov 2025): SBC-layer deepfake detection w/ codec-aware preprocessing
  (zero prior art); LLM SIP-ladder explanation from PCAP; external PQC readiness scoring.
