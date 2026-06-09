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
from .ca_compliance import _norm


def _teams(cfg: NormalizedConfig) -> SipInterface | None:
    return cfg.teams_interface()


def _roots(iface: SipInterface | None) -> set[str]:
    # Normalize so the same root named two ways across firmware/export versions
    # ("DigiCert Global Root G2" vs "DigiCertGlobalRootG2") does not read as drift.
    if iface and iface.tls_context:
        return {_norm(r) for r in iface.tls_context.trusted_root_ids}
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

    # Trust store — the failover-during-CA-migration killer. Only comparable when
    # both nodes authoritatively enumerate their trust store; otherwise an absent
    # store would read as false drift.
    ac, sc = at.tls_context, st.tls_context
    both_introspectable = bool(ac and sc and ac.introspectable and sc.introspectable)
    if not both_introspectable:
        add("HA.DRIFT.TRUST_STORE_UNVERIFIABLE",
            "Trust store drift not verifiable from these sources",
            Severity.LOW,
            "At least one node imports its trust store separately (it is not in this "
            "export), so root-CA drift cannot be compared here. Confirm both nodes "
            "carry identical root CAs out-of-band.",
            "Verify the active and standby Teams TLS trust stores match.")
    elif _roots(at) != _roots(st):
        a_raw, s_raw = set(ac.trusted_root_ids), set(sc.trusted_root_ids)
        missing_on_standby = sorted(r for r in a_raw if _norm(r) not in _roots(st))
        extra_on_standby = sorted(r for r in s_raw if _norm(r) not in _roots(at))
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

    # SRTP — a failover onto an SRTP-off standby drops Teams media (no audio).
    if bool(at.srtp_enabled) != bool(st.srtp_enabled):
        add("HA.DRIFT.SRTP",
            "SRTP (media encryption) setting differs between nodes",
            Severity.HIGH,
            f"Active SRTP={bool(at.srtp_enabled)} vs standby SRTP={bool(st.srtp_enabled)}; "
            "a failover to the SRTP-off node would drop Teams media (no audio).",
            "Enable SRTP on the Teams media leg on both nodes.")

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
