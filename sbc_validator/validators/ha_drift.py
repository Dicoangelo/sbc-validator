"""
HA configuration drift detection.

Compares two normalized configs (an Active node and its Standby) and reports the
policy fields that MUST match for a clean failover. Node-identity fields that
legitimately differ (FQDN, media IPs) are intentionally NOT compared; only the
settings that, if drifted, cause calls to fail when the standby takes over.

The headline case is the trust store: if the standby's required-root-CA set
drifts from active, a failover during Microsoft's 2026 CA rotation lands on a
node whose trust is incomplete and calls hard-stop. That is exactly the silent
failure HA is supposed to prevent, so it is rated CRITICAL.
"""
from __future__ import annotations

from ..models import NormalizedConfig, SipInterface
from .base import Finding, Severity


def _teams(cfg: NormalizedConfig) -> SipInterface | None:
    return cfg.teams_interface()


def _roots(iface: SipInterface | None) -> set[str]:
    if iface and iface.tls_context:
        return set(iface.tls_context.trusted_root_ids)
    return set()


def ha_diff(active: NormalizedConfig, standby: NormalizedConfig) -> list[Finding]:
    findings: list[Finding] = []

    def add(check_id, title, sev, detail, remediation):
        findings.append(Finding(check_id=check_id, title=title, severity=sev,
                                detail=detail, remediation=remediation,
                                locator="active vs standby", domain="HA"))

    # Structural: same set of interface roles on both nodes.
    a_roles = {i.role for i in active.sip_interfaces}
    s_roles = {i.role for i in standby.sip_interfaces}
    if a_roles != s_roles:
        add("HA.DRIFT.ROLES",
            "Interface role set differs between nodes",
            Severity.MEDIUM,
            f"Active roles {sorted(a_roles)} != standby roles {sorted(s_roles)}; "
            "the standby is not a faithful copy of active.",
            "Reconcile the standby's SIP interface set with active.")

    at, st = _teams(active), _teams(standby)
    if at is None or st is None:
        add("HA.DRIFT.NO_TEAMS",
            "Teams interface missing on one node",
            Severity.HIGH,
            f"Teams interface present on active={at is not None}, "
            f"standby={st is not None}; failover would drop the Teams leg.",
            "Configure the Teams SIP interface identically on both nodes.")
        return findings

    # Trust store — the failover-during-CA-migration killer.
    a_roots, s_roots = _roots(at), _roots(st)
    if a_roots != s_roots:
        missing_on_standby = sorted(a_roots - s_roots)
        extra_on_standby = sorted(s_roots - a_roots)
        add("HA.DRIFT.TRUST_STORE",
            "Trust store (root CAs) drifted between nodes",
            Severity.CRITICAL,
            "Standby trust store does not match active. A failover during the "
            "2026 CA rotation would land on a node with a different trust set and "
            f"calls hard-stop. Missing on standby: {missing_on_standby or 'none'}; "
            f"extra on standby: {extra_on_standby or 'none'}.",
            "Sync the Teams TLS trust store so both nodes carry the identical root CAs.")

    # Transport / mTLS.
    if (at.transport or "") != (st.transport or ""):
        add("HA.DRIFT.TRANSPORT",
            "Teams SIP transport differs between nodes",
            Severity.HIGH,
            f"Active transport='{at.transport}' vs standby='{st.transport}'.",
            "Set the same Teams transport (TLS) on both nodes.")
    a_mtls = bool(at.tls_context and at.tls_context.mtls_enabled)
    s_mtls = bool(st.tls_context and st.tls_context.mtls_enabled)
    if a_mtls != s_mtls:
        add("HA.DRIFT.MTLS",
            "mTLS setting differs between nodes",
            Severity.HIGH,
            f"Active mTLS={a_mtls} vs standby mTLS={s_mtls}.",
            "Enable mTLS on the Teams TLS context on both nodes.")

    # Keep-alive / normalization / codecs / dtmf.
    if at.options_keepalive != st.options_keepalive:
        add("HA.DRIFT.KEEPALIVE",
            "SIP OPTIONS keep-alive differs between nodes",
            Severity.MEDIUM,
            f"Active={at.options_keepalive} vs standby={st.options_keepalive}.",
            "Enable OPTIONS keep-alive on both nodes.")
    if (at.normalization_profile or None) != (st.normalization_profile or None):
        add("HA.DRIFT.NORMALIZATION",
            "SIP normalization profile differs between nodes",
            Severity.MEDIUM,
            f"Active='{at.normalization_profile}' vs standby='{st.normalization_profile}'.",
            "Apply the same normalization profile on both nodes.")
    if set(at.offered_codecs) != set(st.offered_codecs):
        add("HA.DRIFT.CODECS",
            "Offered codec set differs between nodes",
            Severity.MEDIUM,
            f"Active={sorted(at.offered_codecs)} vs standby={sorted(st.offered_codecs)}.",
            "Align the codec lists on both nodes.")
    if (at.dtmf_method or None) != (st.dtmf_method or None):
        add("HA.DRIFT.DTMF",
            "DTMF method differs between nodes",
            Severity.LOW,
            f"Active='{at.dtmf_method}' vs standby='{st.dtmf_method}'.",
            "Use the same DTMF method on both nodes.")

    return findings
