"""
Risk scoring. Maps findings to a 0-100 risk score and a deploy verdict.
Severity-weighted; any CRITICAL caps the verdict at BLOCK.
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


def score(findings: list[Finding]) -> dict:
    raw = sum(_WEIGHT[f.severity] for f in findings)
    risk = min(100, raw)
    has_critical = any(f.severity == Severity.CRITICAL for f in findings)
    has_high = any(f.severity == Severity.HIGH for f in findings)
    if has_critical:
        verdict = "BLOCK"
    elif has_high:
        verdict = "REVIEW"
    else:
        verdict = "PASS"
    return {"risk_score": risk, "verdict": verdict,
            "counts": {s.name: sum(1 for f in findings if f.severity == s) for s in Severity}}
