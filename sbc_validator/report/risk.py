"""
Risk scoring. Maps findings to a 0-100 risk score and a deploy verdict.

The verdict must never contradict the score: a tool whose whole value is "trust
the verdict" cannot print "Risk 96/100 · PASS". So the verdict is the WORSE of two
signals: the worst single finding (any CRITICAL -> BLOCK, any HIGH -> REVIEW) AND the
accumulated score (a wall of MEDIUMs that piles up to a high score is itself
deploy-blocking, even with no individual HIGH/CRITICAL). The score gate only ever
ESCALATES; it never downgrades a HIGH/CRITICAL verdict.

Thresholds are pinned against the real sample fleet: the highest legitimately-PASS
config scores 16, the lowest REVIEW scores 21, so a REVIEW floor at 20 and a BLOCK
floor at 60 fix the contradiction without flipping any clean config.
"""
from __future__ import annotations

from ..validators.base import Finding, Severity

_WEIGHT = {
    Severity.INFO: 0,
    Severity.LOW: 2,
    Severity.MEDIUM: 6,
    Severity.HIGH: 15,
    Severity.CRITICAL: 40,
}

# Score gates: accumulated risk that warrants escalation on its own.
_REVIEW_AT = 20   # just above the worst legitimately-clean config (16)
_BLOCK_AT = 60    # a high pile of sub-HIGH findings is not deployable


def score(findings: list[Finding]) -> dict:
    raw = sum(_WEIGHT[f.severity] for f in findings)
    risk = min(100, raw)
    has_critical = any(f.severity == Severity.CRITICAL for f in findings)
    has_high = any(f.severity == Severity.HIGH for f in findings)
    if has_critical or risk >= _BLOCK_AT:
        verdict = "BLOCK"
    elif has_high or risk >= _REVIEW_AT:
        verdict = "REVIEW"
    else:
        verdict = "PASS"
    return {"risk_score": risk, "verdict": verdict,
            "counts": {s.name: sum(1 for f in findings if f.severity == s) for s in Severity}}
