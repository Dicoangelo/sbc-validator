# Patent / Freedom-to-Operate Brief (for counsel)

Not legal advice. A founder-prepared brief to hand an IP attorney so the FTO opinion is
cheap and targeted. Grounded in the prior-art sweep (`06-PRIOR-ART-AND-COMPETITORS.md`).
Goal: file the two HIGH-value claims **narrowed to survive** the live art, and clear the
path before any public disclosure widens (a public scanner launch starts a clock).

## Claims we want to pursue (priority order)

### Claim 1 (HIGH) — On-prem protocol-aware SIP-PCAP explainer
**Plain statement:** a method that tokenizes a SIP/SDP/RTP packet capture along the
protocol field tree with timing-gap tokens and normalized identifiers, runs an on-prem
model to reconstruct the SIP ladder, and maps each detected failure to a config-remediation
domain and fix, without the capture leaving the customer boundary.
- **Prior art to design around:**
  - **LLMcap** (arXiv 2407.06085) — LLM for unsupervised PCAP failure detection incl SIP.
    *Distinguish:* LLMcap is generic anomaly detection; we claim SIP-ladder reconstruction
    + per-domain config-fix mapping + the on-prem/identifier-normalization privacy step.
  - **US 12432128** ("specialized LLMs for network traffic analysis") and the indexed
    "LLM receives call-flow descriptions -> predicts root error for VOIP/SIP." *Distinguish:*
    their input is a structured call-flow DESCRIPTION; ours is a RAW capture we tokenize.
    (PDF was OCR-unreadable in our sweep — counsel must pull clean claims.)
  - **US 12513176** ("LLM malicious packet detection") — security framing, lower overlap.
  - **PLUME** (arXiv 2603.13647) / **netFound** (arXiv 2310.17025) — protocol-aware
    tokenization as a general method is now published; claim the **SIP-specific
    instantiation + the config-domain mapping**, not tokenization in the abstract.
- **Novel hooks worth claiming:** identifier-normalization-as-privacy (tokens carry no raw
  locator) tied to an air-gapped execution guarantee; timing-gap tokens that surface a
  stalled OPTIONS keepalive; the deterministic-verdict-wins guardrail.

### Claim 2 (HIGH) — External SBC-media-tap deepfake detection
**Plain statement:** detecting synthetic/spoofed voice by tapping SBC media out-of-band
(SIPREC / media-fork sidecar) with codec-aware preprocessing, as an external tool on a
third-party SBC.
- **Prior art:** none found at the SBC-tap layer (Pindrop is contact-center/IVR; ASVspoof
  is datasets/models, not SBC-tap). Looks clean. **Highest novelty-to-prior-art ratio.**
- *Note:* license the detector (Pindrop/ASVspoof-trained); patent the **SBC-tap + codec-aware
  preprocessing pipeline**, not the classifier.

## Claims to file defensively / MEDIUM
- **Multi-vendor config normalization + policy (OPA/Rego) evaluation.** *Prior art that
  narrows it:* **US 11418515** ("multi-vendor support for network access control policies"),
  **US 12192241** ("intent-based policy configuration"), and the CNCF/Infosys "OPA in
  telecom" pattern. Claim the **SBC-Layer-5-specific** normalization (SIP/SDP semantics,
  the observability-semantics matrix), not generic multi-vendor policy.
- **External PQC migration readiness scoring for SIPS/SRTP** — no direct art; MED-HIGH.
- **Out-of-band SHAKEN CPS retrieval + PASSporT verification** — only ATIS-1000105 itself.

## Patents to keep clear of (design-around list, consolidated)
| Patent | Holder/area | Our posture |
|---|---|---|
| US 12432128 / 12513176 | LLM-on-network-traffic | distinguish on raw-pcap input + SIP-ladder + config mapping |
| US 11418515 / 12192241 | multi-vendor / intent policy | narrow our normalization claim to SBC L5 |
| US 11153180 / 11683240 | "assisted intent builder" | relevant only to the (deferred) assisted-remediation feature |
| US 10009365 / US 9729509 | Ribbon SIP-anomaly | we are external + pre-deploy + cross-vendor; distinguish |
| US 11348048 | telecom digital-twin deviation | we are config-static + capture, not a live twin |
| US 9712392 | Google SIP endpoint config | endpoint-config, not external validation |

## Sequencing (the disclosure clock)
1. **Before** launching the public outside-in scanner (a public disclosure), file at least a
   provisional on Claim 1 (the scanner demonstrates the readiness-grading method publicly).
2. Get the clean claim text for US 12432128 / US 11418515 (counsel pulls from USPTO) and
   confirm the design-arounds hold.
3. File Claim 2 (deepfake SBC-tap) opportunistically; it is the cleanest and is not
   disclosed by anything shipping today.

## One-line ask to the attorney
"FTO + provisional on two claims: (1) on-prem raw-PCAP SIP-ladder explainer with
config-domain mapping, narrowed against LLMcap / US12432128; (2) external SBC-media-tap
deepfake detection. Plus a quick clearance read on US11418515 before we file a multi-vendor
config-normalization claim. We have a public scanner launch pending, so Claim 1 is
time-sensitive."
