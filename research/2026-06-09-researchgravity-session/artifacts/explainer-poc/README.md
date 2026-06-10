# On-Prem SIP Explainer POC

Proof scaffold for the flagship moat-consistent AI feature. Full design in
`../../07-ONPREM-EXPLAINER-POC.md`. This directory is **contained** (not wired into
`sbc_validator/` — the parallel session owns that tree). Promote deliberately.

## What runs today
- `sip_tokenizer.py` — a working protocol-aware SIP tokenizer over the repo's existing
  `sip_trace.SipMsg` event shape. Pure stdlib. `python sip_tokenizer.py` prints a token
  stream and asserts (a) no raw IP/FQDN/Call-ID survives (privacy = the air-gap guarantee)
  and (b) the 488-reject / private-SDP-IP / topology-leak are all captured structurally.

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
