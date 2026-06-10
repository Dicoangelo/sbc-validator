# Track 2 — On-Prem SIP Explainer POC (the flagship, moat-consistent)

**Goal:** turn `explain` from a deterministic pcap post-mortem into an AI explainer that
**runs inside the customer air gap** (no cloud LLM, no data egress), so the marquee AI
feature *reinforces* the "raw captures never leave" moat instead of contradicting it.

**Why this is the state-of-the-art move (from `06-PRIOR-ART`):** PLUME (arXiv 2603.13647)
showed a 140M-param on-prem protocol-aware model **beats Claude Opus 4.6 / GPT-5.4** at
next-packet prediction at 600x fewer params, running on one GPU. netFound (arXiv
2310.17025, UCSB, open weights on HuggingFace) is a ready protocol-aware foundation model
to fine-tune. LLMcap (arXiv 2407.06085) is the SIP-PCAP prior art to design around. The
patentable delta is **SIP-ladder reconstruction + per-domain config-fix mapping**, not
"an LLM reads a PCAP."

## What the repo already gives us (so this is buildable, not vapor)
- `sbc_validator/pcap.py` — pure-stdlib classic-pcap + SLL2 reader (no scapy).
- `sbc_validator/sip_trace.py` — reconstructs the SIP ladder, RTP flow direction, TLS
  alerts, maps causes to domains B/C/D/E/F.
- The 8-domain validator vocabulary + `samples/` capture generator.

So the deterministic ladder + the domain mapping ALREADY EXIST. The POC adds a
**protocol-aware tokenizer** over the parsed SIP/SDP/RTP events and a **small on-prem model**
that learns normal-vs-failing call grammar, producing (a) a plain-English root cause and
(b) a confidence the deterministic verdict can gate on. The model never overrides the
deterministic verdict (the "silence beats a wrong verdict" rule still holds); it produces
the *explanation*, exactly where AI belongs per VISION_PRODUCT_ARCHITECTURE.

## Architecture (3 stages)

```
capture.pcap
   |  pcap.py + sip_trace.py  (EXISTING, deterministic)
   v
parsed events:  [SIP req/resp, SDP offer/answer, RTP flow, TLS alert] + domain tags
   |  sip_tokenizer.py  (NEW — protocol-aware, PLUME-style)
   v
token stream (field-tree tokens + gap tokens + normalized identifiers)
   |  explainer model  (NEW — netFound fine-tune OR a small from-scratch encoder)
   v
{ root_cause_text, failure_class, confidence, domain }  -> feeds the existing `explain` report
```

### Stage 1 — Protocol-aware SIP tokenizer (the novel, buildable-now piece)
PLUME's recipe, adapted to SIP: split along the dissector field tree (method, status,
header name/value, SDP m=/c=/a= lines, RTP PT), emit **gap tokens** for inter-packet
timing buckets (catches OPTIONS-keepalive gaps, the CallTower failure), and **normalize
identifiers** (FQDNs -> `<FQDN>`, IPs -> `<IP-PRIVATE>` / `<IP-PUBLIC>`, Call-IDs ->
`<CID>`, tags/branches -> `<TAG>`) so the model learns structure, not memorized values.
This normalization is ALSO the privacy layer: tokens carry no raw locators, consistent
with the anonymized-export discipline. A first cut ships in `artifacts/explainer-poc/
sip_tokenizer.py` (this session) and runs on the existing parsed events with zero new deps.

### Stage 2 — The model (two paths, pick by resource)
- **Path A (fastest, recommended POC): fine-tune netFound.** Open weights (53M-663M),
  permissive license, protocol-aware tokenizer already in its design. Fine-tune on a SIP
  PCAP corpus for two heads: masked-token (self-supervised, learns call grammar) +
  failure-class (supervised on the domain tags sip_trace already produces). Runs on-prem,
  CPU-inferable at 53M for the explanation path.
- **Path B (cleanest IP, more work): small from-scratch encoder** (~10-50M) over the SIP
  tokenizer, masked-LM pretrain + failure-class fine-tune. Higher patent clarity (our
  tokenizer + our weights), no upstream-license question. Defer unless Path A licensing
  or fit disappoints.

### Stage 3 — Integration (no verdict contamination)
The model output is attached to the EXISTING deterministic `explain` result as an
`ai_explanation` block with a confidence. Rule: **if the model and the deterministic
mapping disagree, the deterministic mapping wins and the AI line is suppressed** (or shown
as "low confidence"). The verdict path stays 100% deterministic. This is the guardrail
that keeps the trust discipline intact.

## Training-data pipeline (and the honest dependency)
- **Source:** the same anonymized capture corpus the consultancy channel (Direction 2)
  brings in. One asset, two returns: it is the data moat (Finding 2) AND the training set.
- **Bootstrap before real data:** the repo's `samples/` capture generator can synthesize a
  labeled corpus (each failure class -> N captures with jitter) to stand up the harness and
  prove the pipeline end-to-end TODAY, before a single customer capture exists.
- **Honest dependency:** a *production-grade* model needs real, diverse captures (and a GPU
  for Path A pretraining). The POC proves the architecture on synthetic + a handful of real
  captures; production accuracy is gated on the same config/capture-acquisition unlock that
  gates everything else (CONFIG-REQUEST / the channel). State this plainly; do not claim a
  trained model exists.

## Eval plan
- **Intrinsic:** masked-token accuracy on held-out captures (PLUME reports 74-97%; target
  comparable on SIP).
- **Task:** failure-class macro-F1 vs the deterministic domain tags (the model should agree
  with the deterministic mapping on the easy cases and add value on the ambiguous ones).
- **Privacy assertion (must pass):** a test that proves NO raw FQDN/IP/Call-ID survives
  tokenization (only normalized placeholders) — the same guarantee as `report/anonymize.py`.
- **Air-gap assertion:** the explainer path makes zero network calls (mirror the existing
  `--network none` smoke). This is the whole point.

## Patent posture (from `06-PRIOR-ART`, for counsel)
- Narrow the claim to: *protocol-aware SIP/SDP tokenization with timing-gap tokens and
  identifier normalization, feeding an on-prem model that reconstructs a SIP ladder and maps
  each failure to a config-remediation domain.* Prior art to cite around: LLMcap
  (network-generic), US12432128 (call-flow-description input, not raw-pcap), US11418515
  (multi-vendor config-policy). The on-prem + normalization-as-privacy angle is a
  differentiator worth claiming.

## POC deliverables in this session (contained, no repo collision)
- `artifacts/explainer-poc/sip_tokenizer.py` — runnable protocol-aware SIP tokenizer over
  the existing parsed-event shape, with identifier normalization + gap tokens.
- `artifacts/explainer-poc/README.md` — how to wire it to `sip_trace.py`, the two model
  paths, and the synthetic-corpus bootstrap command.
- (Deferred to a deliberate promote step, not scattered into the package now:) `train.py` /
  `eval.py` harness — sketched in the README; build when you greenlight promoting this into
  `sbc_validator/` proper (coordinate with the parallel session for file ownership).
