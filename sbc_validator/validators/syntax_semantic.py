"""
Domain A — Syntax / Semantic baseline.

The structural-integrity gate that runs before the domain-specific validators:
it catches configs that are malformed, internally inconsistent, or missing the
pieces the B/C/D/E checks depend on. Cheap to run, high signal, vendor-neutral.

  * config parsed but produced no SIP interfaces (likely structural/parse fault)
  * SBC FQDN missing or malformed (downstream cert/host matching can't run)
  * duplicate SIP interface names (ambiguous routing)
  * an interface declares TLS transport but resolves no TLS context (dangling ref)
"""
from __future__ import annotations

import re

from ..models import NormalizedConfig
from .base import AbstractValidator, Finding, Severity, ValidatorResult

_FQDN_RE = re.compile(r"^(?=.{1,253}$)([a-zA-Z0-9_](-?[a-zA-Z0-9_])*\.)+[a-zA-Z]{2,}$")


class SyntaxSemanticValidator(AbstractValidator):
    domain = "A"

    def validate(self, config: NormalizedConfig) -> ValidatorResult:
        res = ValidatorResult(domain=self.domain)

        if not config.sip_interfaces:
            res.add(Finding(
                check_id="A.STRUCT.NO_SIP_INTERFACES",
                title="No SIP interfaces parsed from config",
                severity=Severity.HIGH,
                detail="The config parsed but yielded zero SIP interfaces, which "
                       "usually means a structural/parse fault or an unsupported export.",
                remediation="Verify the export is complete and in the expected format.",
            ))

        # FQDN presence + format
        if not config.sbc_fqdn:
            res.add(Finding(
                check_id="A.SEM.MISSING_FQDN",
                title="SBC FQDN not set",
                severity=Severity.MEDIUM,
                detail="No SBC FQDN found; certificate CN/SAN matching and Teams "
                       "host validation cannot be fully evaluated.",
                remediation="Set the SBC FQDN in the configuration.",
            ))
        elif not _FQDN_RE.match(config.sbc_fqdn):
            res.add(Finding(
                check_id="A.SYN.FQDN_FORMAT",
                title="SBC FQDN is malformed",
                severity=Severity.MEDIUM,
                detail=f"'{config.sbc_fqdn}' is not a well-formed fully-qualified domain name.",
                remediation="Correct the SBC FQDN to a valid hostname (e.g. sbc01.example.com).",
            ))

        # Duplicate interface names
        seen, dupes = set(), set()
        for iface in config.sip_interfaces:
            if iface.name in seen:
                dupes.add(iface.name)
            seen.add(iface.name)
        for name in sorted(dupes):
            res.add(Finding(
                check_id="A.SEM.DUP_INTERFACE",
                title=f"Duplicate SIP interface name '{name}'",
                severity=Severity.MEDIUM,
                detail="Two interfaces share a name, which makes routing/binding ambiguous.",
                remediation="Give each SIP interface a unique name.",
                locator=f"iface '{name}'",
            ))

        # Dangling TLS reference: declares TLS but no context resolved
        for iface in config.sip_interfaces:
            if (iface.transport or "").lower() == "tls" and iface.tls_context is None:
                res.add(Finding(
                    check_id="A.SEM.DANGLING_TLS",
                    title=f"Interface '{iface.name}' uses TLS but has no TLS context",
                    severity=Severity.HIGH,
                    detail="TLS transport is declared but no TLS profile resolved; the "
                           "interface cannot complete a handshake as configured.",
                    remediation="Bind a valid TLS context to the interface.",
                    locator=f"iface '{iface.name}'",
                ))

        return res
