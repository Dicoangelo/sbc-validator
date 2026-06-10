# On-Prem SIP Explainer POC

Proof scaffold for the flagship moat-consistent AI feature. Full design in
`../../07-ONPREM-EXPLAINER-POC.md`. This directory is **contained** (not wired into
`sbc_validator/` — the parallel session owns that tree). Promote deliberately.

## What runs today
- `sip_tokenizer.py` — a working protocol-aware SIP tokenizer over the repo's existing
  `sip_trace.SipMsg` event shape. Pure stdlib. `python sip_tokenizer.py` prints a token
  stream and asserts (a) no raw IP/FQDN/Call-ID survives (privacy = the air-gap guarantee)
  and (b) the 488-reject / private-SDP-IP / topology-leak are all captured structurally.
- `make_corpus.py` — synthetic labeled corpus generator: 5 failure classes (CLEAN,
  REJECT_488, ONE_WAY_AUDIO, TOPOLOGY_LEAK, OPTIONS_BLACKHOLE) with jittered IPs/codecs/
  timing, written as wire-valid pcaps and parsed by the REAL `sbc_validator.sip_trace`
  engine, then tokenized. Privacy gate asserted per-sample (no Call-ID survives).
- `eval_baseline.py` — stdlib multinomial naive Bayes floor over token counts.

### Results (2026-06-10, seed 2026, 100/class)
500 calls, 80/20 split: **accuracy 1.000 (100/100), recall 1.00 on all 5 classes,
vocab = 26 tokens.** Top discriminative tokens per class are the causally-correct
signals, not artifacts: `RTP:ONEWAY` + `SDP:C=<IP-PRIVATE>` (one-way audio),
`METHOD:OPTIONS` + `GAP:KEEPALIVE_WINDOW` (the CallTower blackhole), `STATUS:488` +
`CODEC:G729` (codec reject), `TOPOLOGY_LEAK:CONTACT` (leak). Honest read: 100% on
cleanly-separated synthetic classes is the EXPECTED floor, not an achievement; its value
is proving the pipeline (capture -> real parser -> tokens -> classifier) end-to-end and
that the tokenization preserves causal structure. The netFound fine-tune (Path A) earns
its keep only on real, ambiguous captures — which the consultancy channel supplies.
Regenerate: `make_corpus.py --per-class 100` then `eval_baseline.py corpus.jsonl`
(corpus.jsonl is generated, not committed).

## Wiring it to the real parser (one adapter call)
```python
from sbc_validator.sip_trace import analyze            # existing deterministic pass
# analyze() already groups SipMsg per call_id and computes tls_alert + one-way RTP.
# Expose the per-call SipMsg list + signals, then:
from sip_tokenizer import tokenize_call
tc = tokenize_call(call_msgs, tls_alert_code=alert, rtp_oneway=one_way)
# tc.tokens -> model input. The deterministic Diagnosis still drives the verdict.
```

## Bootstrap a labeled corpus BEFORE any customer capture (do this first)
The repo already ships a capture generator under `samples/`. Use it to synthesize a
labeled training set per failure class (codec-488, one-way-audio, TLS-untrusted-root,
OPTIONS-blackhole, topology-leak), with timing/IP jitter, so the harness is provable
end-to-end on synthetic data today. Real captures from the consultancy channel
(Direction 2) then sharpen it — same corpus is the data moat AND the training set.

## Two model paths (pick by resource — see design doc §Stage 2)
- **Path A (recommended POC):** fine-tune **netFound** (open weights, HuggingFace,
  53M-663M, permissive license). Two heads: masked-token (self-supervised call grammar) +
  failure-class (supervised on the domain tags `sip_trace` already emits). On-prem,
  CPU-inferable at 53M.
- **Path B (cleanest IP):** small from-scratch encoder (~10-50M) over this tokenizer.
  Higher patent clarity, no upstream license question. Defer unless Path A disappoints.

## Harness to build at promote-time (sketch, not yet written to avoid scatter)
- `train.py` — load synthetic+real token streams, masked-LM pretrain, failure-class
  fine-tune; checkpoint to a local dir (never a cloud bucket).
- `eval.py` — masked-token accuracy, failure-class macro-F1 vs deterministic tags, the
  privacy assertion, and the zero-network-call (air-gap) smoke.

## The one rule that must never break
The model produces the **explanation**, never the **verdict**. If the model disagrees with
the deterministic domain mapping, the deterministic mapping wins and the AI line is
suppressed / shown low-confidence. "Silence beats a wrong verdict" still governs.
