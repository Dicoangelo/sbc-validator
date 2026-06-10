# Innovation Report: SBC-AutoOps Validator
Generated: 2026-06-10 | Session: sbc-autoops-validato-20260609-235604-69bb2b
Sources: 30+ GitHub repos scanned (2 filters), arXiv sweep, HuggingFace verified
(Mirror of `.agent/research/` session artifact; canonical structures in the session scratchpad.)

## Executive Summary
The dual-filter scan confirms the whitespace AND hands us three concrete assets: the
netFound fine-tune substrate is verified downloadable (MIT, refreshed Mar 2026), the
HOMER org just shipped a modern SIPp-successor (gossipper) that derisks Phase-2 live
probing, and a 2-month-old "AI SIP-pcap analyzer with GPT-4o chat" proves market demand
for AI pcap explanation while making our on-prem differentiation literal: that tool
ships captures to OpenAI; ours never leaves the machine.

## The Viral Choice
**[SIPp](https://github.com/SIPp/sipp)** — the canonical SIP test tool, pushed 2026-06-08.
- Why: when Phase-2 live probing goes beyond the TLS-handshake probe (real INVITE/
  OPTIONS scenario tests against a staging SBC), SIPp is the battle-tested engine.
- Integration: drive SIPp scenarios from validator findings ("validator says codec
  mismatch; here is the SIPp scenario that proves it against staging").

**[HOMER / sipcapture](https://github.com/sipcapture/homer)** — open-source SIP capture +
monitoring, very active.
- Why: HEP is the de-facto capture transport in serious VoIP shops. An `explain
  --from-hep` ingest makes the explainer consume the captures customers ALREADY collect,
  at fleet scale, with no new instrumentation.

## The Groundbreaker Choice
**[gossipper](https://github.com/sipcapture/gossipper)** — Mar 2026, by the HOMER org.
- Novel: SIPp-compatible scenarios + RTP/SRTP/WebRTC media + HTTP control API + HEP
  observability in one modern platform.
- Why it matters: a credible org rebuilding SIP load-testing NOW = the ecosystem is
  modernizing around exactly our layer. Partner/integration candidate, and the cleaner
  Phase-2 probe engine if SIPp's age shows.
- Caveat: 3 months old; watch maturity.

## Competitor signal (the important one)
**[kranti-sip-pcap-analyzer](https://github.com/krantikumara/-kranti-sip-pcap-analyzer)**
— Apr 2026: "AI-powered SIP PCAP analyzer with call flow, hold/resume detection, and
GPT-4o chat."
- Read: demand for AI pcap explanation is real and arriving bottom-up. Its architecture
  sends customer captures to a cloud LLM — the exact thing a security-reviewed telecom
  shop cannot do. Our `explain --ai` (shipped 397add1) does it on-prem with zero egress.
  This repo is the marketing foil: same feature, opposite trust model.

## Additional Discoveries
| Name | Why it matters |
|---|---|
| [DVRTC](https://github.com/EnableSecurity/DVRTC) (EnableSecurity, Mar 2026) | Intentionally-vulnerable RTC lab (SIP enumeration, RTP bleed, TURN abuse). Free test substrate for domain-S checks; natural fixture set for the future managed-fuzz service (the sippts fuzzer vacuum). |
| [sipstress](https://github.com/achrafka/sipstress) (May 2026) | Same-space micro-tool (SIP call gen + diagnostics + PDF reports). Single-purpose; not a threat; confirms practitioner appetite for diagnostic reports. |
| [sipgo](https://github.com/emiago/sipgo) | Fast Go SIP library if the probe ever outgrows stdlib ssl. |

## HuggingFace verification (the build-path de-risk)
- **netFound weights CONFIRMED:** `snlucsb/netFound-small` / `-base` / `-large`,
  refreshed 2026-03-09, MIT, safetensors (+ older `netFound-640M-base`). The explainer
  fine-tune path is real, not aspirational.
- **Deepfake sidecar bootstrap:** open ASVspoof5-trained models exist (MattyB95
  AST/ViT variants, 314-390 downloads). The sidecar can prototype on open weights
  before any Pindrop licensing conversation.

## arXiv
| Title | ID | Key insight |
|---|---|---|
| LLMcap | 2407.06085 | flagship prior art; design-around = ladder + config-domain mapping |
| PLUME | 2603.13647 | tokenization recipe adopted in `explain --ai` |
| netFound | 2310.17025 | the fine-tune substrate (weights verified above) |
| Side-channel VoIP profiling | 2306.00095 | encrypted-SIP VAD side-channel; future privacy-domain check |
Recent arXiv is otherwise thin on SIP (most results 2006-2023): the frontier for this
domain lives in industry docs + GitHub, which is why the dual-filter GitHub scan is the
right instrument.

## Search Methodology
- Viral filter: `SIP testing OR validation OR diagnostics stars:>500 pushed:>2026-05-01` (26 hits)
- Groundbreaker filter: `SIP OR VoIP OR "session border" stars:10..200 created:>2026-03-01` (22 hits)
- arXiv: export API, "session border controller" OR "SIP protocol" OR "VoIP security", by date
- HuggingFace: api/models search `netFound`, `asvspoof`
- URLs logged to session: 25 total (see sources CSV in the session store)
