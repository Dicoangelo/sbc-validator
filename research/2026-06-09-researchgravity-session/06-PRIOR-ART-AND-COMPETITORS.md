# Prior Art and Competitor Landscape — SBC-AutoOps

Deep prior-art sweep run 2026-06-09/10 (WebSearch + arXiv + USPTO). Goal: find any
academic paper or identical project, classify each as PRIOR-ART (narrows our patent /
we must design around), BUILD-ON (a method/asset we should adopt), or COMPETITOR, and
ground-truth the whitespace claim. Bottom line up front: **no independent, multi-vendor,
pre-deployment SBC config validator exists**; the closest tools are single-vendor or
post-deployment. The flagship LLM-PCAP-explainer has real prior art (LLMcap) and a clear,
air-gap-consistent build path (netFound / PLUME, on-prem protocol-aware models).

---

## A. Academic papers

| Paper | What it is | Classification | Implication for us |
|---|---|---|---|
| **LLMcap** (arXiv 2407.06085) | Self-supervised LLM (masked-LM) for **unsupervised PCAP failure detection**; trained on 1.26 GB PCAP incl **SIP**, VoLTE, VoNR | **PRIOR ART (flagship)** | This is the cited prior art for our LLM-on-PCAP claim. It is network-generic anomaly detection. Our patentable delta = **SIP-ladder reconstruction + mapping each failure to a config-domain + the fix**, not "LLM reads a PCAP." Narrow the claim accordingly. |
| **PLUME** (arXiv 2603.13647, Mar 2026) | 140M-param network-native foundation model for 802.11 traces; **protocol-aware tokenizer** (splits along the dissector field tree, gap tokens for timing, normalized IDs; 6.2x shorter than BPE); **beats Claude Opus 4.6 / GPT-5.4 at 600x fewer params**; runs on a single GPU on-prem at ~zero marginal cost; AUROC >= 0.99 zero-shot anomaly detection | **BUILD-ON (method) + partial PRIOR ART** | The single most important paper for us. (1) It proves a small **on-prem** protocol-aware model resolves our core tension: AI explanation WITHOUT sending customer data to a cloud LLM (keeps the air-gap moat intact). (2) The "SIP tokenization scheme" the vault wanted to patent is now partly anticipated as a general method; the **SIP-specific instantiation** is the patentable delta. It is 802.11, not SIP, so **SIP adaptation is open whitespace.** |
| **netFound** (arXiv 2310.17025, UCSB SNL) | Open-source network foundation model; **protocol-aware tokenizer**, multi-modal embedding, hierarchical transformer; 53M-663M params; **pretrained weights on HuggingFace under permissive license**; tasks: traffic classification, intrusion/APT detection | **BUILD-ON (asset)** | A ready, open, on-prem foundation model we can **fine-tune on SIP PCAPs** instead of building from scratch. The fastest credible path to the flagship explainer that still respects local-first. Pair with PLUME's tokenization. |
| Sentinels of the Stream (arXiv 2402.07950) | Position paper: LLMs for dynamic packet classification in SDNs | Context | Confirms the LLM-on-traffic direction is an active 2024+ research front. |
| VoIP Emergency LLM (arXiv 2412.16176) | LLM real-time speech reconstruction + call prioritization for emergency VoIP (RAG) | Adjacent | Different problem (media/transcription), but same buyer adjacency (life-safety VoIP, our regulated ICP). |
| SIP-DDoS ML corpus (MDPI 2020; PLOS One Jun 2025 "Adaptive DDoS detection ... transfer learning"; ACM/ResearchGate 2020-2025) | ML/RNN anomaly + DDoS detection on SIP headers; ~98.9% accuracy reported | Adjacent (runtime security) | Post-deployment signaling-security, not pre-deploy config validation. Confirms the ML-on-SIP field is mature for *security*, empty for *config correctness*. |

**Net read on papers:** the AI-on-network-traffic field is hot and converging on
**on-prem, protocol-aware foundation models** (PLUME, netFound) precisely because cloud
LLMs are too expensive and privacy-hostile for network data. That trend is a tailwind: it
is the same local-first thesis the product is already built on. Our flagship explainer
should be a fine-tuned on-prem protocol-aware model, NOT a cloud LLM API call (which would
contradict the air-gap moat on the marquee feature).

## B. Commercial landscape (the "same exact project" check)

| Player | Multi-vendor? | Pre-deploy? | Independent? | Verdict |
|---|---|---|---|---|
| **SBC-AutoOps (us)** | Yes (4) | Yes | Yes | the only one in all three columns |
| **Ribbon LEAP** | No (Ribbon-only) | Partial (software-upgrade test automation, learns live call flows, generates test scripts) | No (vendor) | Closest competitor; the "LEAP but cross-vendor" foil. Single-vendor by construction. |
| **Oracle CN-SBC test suite** | No (Oracle-only) | Yes (REST test cases in CD pipeline) | No (vendor) | Proves pre-deploy CI testing is wanted; locked to Oracle. |
| **IR Prognosis** | **Yes** (AudioCodes/Oracle/Sonus...) | No (runtime monitoring) | Yes | The multi-vendor incumbent, but **post-deployment** observability. "Smoke detector after the fire." Does not validate a config before commit. |
| **Frequentis Cluster Config Mgr** | No | Config lifecycle/backup-restore | No (vendor) | Single-vendor config management, not validation. |
| **TelcoBridges** | No (vendor) | Educational (TLS/mTLS/SRTP guides) + cert-deadline blog | No | Potential channel/partner; publishes the exact pain content. |
| **Consultancies**: eGroup/Enabling Technologies, Server Consultancy (UK), ChangePilot, Maxime Hiez, erik365, johndeletre, JD.Blog | per-engagement | **Manual** cert validation | Yes | **This is the channel, not a competitor.** They do MC1235747 remediation by hand with no multi-vendor tool. Confirms both the whitespace and Direction 2 (white-label to the consultancy channel). |
| CNCF/Infosys "OPA in telecom" (Apr 2024) | pattern | data-pipeline validation | n/a | Confirms OPA/Rego-per-vendor config validation is an emerging pattern (supports our patent-MED "config normalization + OPA" claim and a possible Plane-B rule format). |
| Antoine Dhersin "almost-free SBC for DR" (LinkedIn) | n/a | n/a | n/a | A DIY cheap SBC, not a validator. Noise. |

**Whitespace confirmed (negative result is the finding):** an explicit search for an
**"SSL Labs for SIP/SBC" outside-in readiness scanner returned nothing**. Microsoft's own
test endpoint exists but is a raw OPTIONS-ping target, not a graded public tool. Our free
outside-in scanner (Direction 3) is genuine first-mover.

## C. Patent landscape (freedom-to-operate flags for counsel)

New patents surfaced this sweep (in addition to the vault's list: Ribbon US10009365 /
US9729509, Pindrop, US11348048 digital-twin, Google US9712392):

| Patent | Title (as indexed) | Risk to which claim | Action |
|---|---|---|---|
| **US 12432128** | "Efficient generation of specialized LLMs for network traffic analysis" | LLM-on-traffic flagship | **FTO review.** PDF was OCR-corrupted; could not read claims. One search summary attributes a "LLM receives call-flow descriptions -> predicts root error for VOIP/SIP" claim to this family. Our design-around: **raw-PCAP input + ladder reconstruction + config-domain mapping**, vs. their "call-flow description" input. |
| **US 12513176** | "LLM based intelligent malicious packet detection" | LLM-on-packet (security) | Lower risk (security/malicious-detection framing, not config-correctness). FTO note only. |
| **US 11418515** | "Multi-vendor support for network access control policies" | our MED claim: multi-vendor config normalization + OPA | **FTO review** before filing the normalization/policy claim. May narrow it. |
| **US 12192241** | "Network access control intent-based policy configuration" | intent/policy config | Adjacent; note. |
| **US 11153180 / 11683240** | "Intelligent and assisted intent builder" | assisted remediation roadmap | Note for the Phase-2 remediation feature. |

**FTO posture:** our two HIGH-priority claims survive but **must be narrowed against live
art**: (1) the LLM-PCAP claim narrows to SIP-ladder-reconstruction + config-domain-mapping
+ fix (LLMcap and US12432128 sit upstream); (2) the deepfake-SBC-tap claim still looks
clean (no media-fork SBC-sidecar art found). Get a real FTO opinion before any filing.

## D. The one state-of-the-art gap this research fills

The project's flagship AI feature (LLM SIP-ladder explainer) had an unstated tension: using
a **cloud** LLM to explain a capture would send customer signaling data off-box, breaking
the "raw configs/captures never leave" moat that is the whole adoption wedge. **PLUME and
netFound resolve it:** a small, on-prem, protocol-aware foundation model (fine-tuned on
SIP) delivers the explainer **inside the air gap**, beats frontier cloud LLMs at this task
at 600x fewer params, and is provably private. This is the state-of-the-art build path and
it makes the flagship feature *strengthen* the moat instead of contradicting it.

**Recommended next builds (papers -> product):**
1. Prototype the explainer as a fine-tune of **netFound** (open weights) on a SIP-PCAP
   corpus, with **PLUME-style protocol-aware SIP tokenization**. Keep it on-prem; it never
   calls out. This is the technically-defensible, moat-consistent version of `explain`.
2. Build the SIP-PCAP training corpus from the same anonymized-findings + capture pipeline
   the consultancy channel (Direction 2) brings in. The corpus is the moat (Finding 2) AND
   the model's training set: one asset, two returns.
3. Get an FTO opinion narrowing the two HIGH patent claims against LLMcap / US12432128 /
   US11418515 before filing.

## Sources
- LLMcap: https://arxiv.org/abs/2407.06085
- PLUME: https://arxiv.org/abs/2603.13647
- netFound: https://arxiv.org/abs/2310.17025 (code: https://github.com/SNL-UCSB/netFound)
- Sentinels of the Stream: https://arxiv.org/pdf/2402.07950
- VoIP Emergency LLM: https://arxiv.org/html/2412.16176v1
- Adaptive DDoS SIP-VoIP (PLOS One, Jun 2025): https://journals.plos.org/plosone/article?id=10.1371/journal.pone.0326571
- Ribbon LEAP: https://ribboncommunications.com/products/enterprise-products/session-border-controllers-service-providers/learning-enabled-automation-program-leap
- Oracle SBC: https://www.oracle.com/communications/enterprise/session-border-controller/
- IR Prognosis: https://www.ir.com/platforms/session-border-controllers
- eGroup mTLS/AudioCodes: https://egroup-us.com/news/teams-direct-routing-mtls-certificates-audiocodes/
- Server Consultancy 2026 cert: https://www.serverconsultancy.co.uk/teams-direct-routing-certificate/
- Maxime Hiez validate-certs: https://maxime.hiez.ca/en/blog/2026-02-24-audiocodes-how-to-validate-new-certificates-teams-direct-routing
- TelcoBridges deadline: https://telcobridges.com/blog/teams-direct-routing-certificate-update/
- CNCF OPA-in-telecom: https://www.cncf.io/blog/2024/04/08/applicability-of-open-policy-agent-opa-in-telecom-domain/
- USPTO 12432128, 12513176, 11418515, 12192241, 11153180, 11683240 (image-ppubs.uspto.gov)
