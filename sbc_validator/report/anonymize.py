"""
Opt-in anonymization.

DEFAULT IS OFF. Nothing here runs unless the operator passes --share-anon.
Even then, only check_id + severity + ruleset version leave. Locators, FQDNs,
CN/SAN, IPs, file paths and free-text details NEVER leave the trust boundary.

This is what makes the aggregated-failure-pattern moat consent-based and safe.
"""
from __future__ import annotations

import hashlib

from ..validators.base import Finding


def anonymized_payload(findings: list[Finding], vendor: str, ruleset_version: str,
                       org_salt: str) -> dict:
    """Build the minimal, non-reversible payload eligible for export."""
    # Stable but non-identifying org token (salted hash), for de-dup only.
    org_token = hashlib.sha256(f"{org_salt}".encode()).hexdigest()[:16]
    return {
        "schema": "sbc-anon/1",
        "org_token": org_token,
        "vendor": vendor,                       # vendor family only, not instance
        "ruleset_version": ruleset_version,     # freshness assertion
        "findings": [
            {"check_id": f.check_id, "severity": f.severity.name}
            for f in findings
        ],
        # explicitly NOT included: locator, detail, remediation, fqdn, ips, certs
    }
