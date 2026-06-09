"""
Shared validation primitives: Finding, Severity, and the AbstractValidator base.

Findings are intentionally explainable: each carries a human-readable problem,
the remediation, and a stable check_id so the report and (opt-in) anonymized
telemetry can reference it without ever leaking config contents.
"""
from __future__ import annotations

import abc
from dataclasses import dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class Finding:
    check_id: str            # stable, e.g. "C.CA.ROOT_COUNT" — safe to aggregate
    title: str
    severity: Severity
    detail: str              # explainable: what we saw and why it matters
    remediation: str         # concrete next step
    # Locator stays LOCAL only; stripped before any anonymized export.
    locator: str = ""        # e.g. "TlsContext 'Teams' on iface 'Teams-SIP'"
    domain: str = ""         # B/C/D/E — derived from check_id prefix if unset

    def __post_init__(self):
        if not self.domain and self.check_id:
            self.domain = self.check_id.split(".", 1)[0]

    def is_blocking(self) -> bool:
        """True when this finding forces a BLOCK verdict.

        Mirrors the verdict mapping in report/risk.py: only a CRITICAL hard-stops
        a deploy (BLOCK). A HIGH gates to REVIEW, not BLOCK, so it is not
        "blocking" here. (Previously this returned HIGH-or-worse, contradicting the
        scorer.)
        """
        return self.severity >= Severity.CRITICAL

    def is_review_gating(self) -> bool:
        """True when this finding gates a deploy to at least REVIEW (HIGH or worse)."""
        return self.severity >= Severity.HIGH


@dataclass
class ValidatorResult:
    domain: str              # "C", "D", ...
    findings: list[Finding] = field(default_factory=list)

    def add(self, f: Finding) -> None:
        self.findings.append(f)


class AbstractValidator(abc.ABC):
    """One per BCDE domain. Pure function of (config, ruleset) -> findings."""

    domain: str = "?"

    def __init__(self, ruleset: dict):
        self.ruleset = ruleset

    @abc.abstractmethod
    def validate(self, config) -> ValidatorResult:  # config: NormalizedConfig
        ...
