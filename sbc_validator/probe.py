"""
`sbc-validator probe <fqdn>` — outside-in Direct Routing readiness.

Opens a live TLS handshake to an SBC's SIP-TLS listener (and, for reference, to
Microsoft's own Direct Routing edge, which is ground truth), inspects the
presented leaf and the negotiated version/cipher, and grades them against the
SAME signed ruleset the local validator enforces. This is the "verified against
Microsoft's own 2026 infrastructure" path: no config upload, only public
endpoints touched, consistent with the air-gapped trust thesis. It can only see
the edge (handshake + leaf); the other seven domains live in the config behind
the firewall, which is the inside-out upsell.

The socket layer is INJECTED (the `connector` arg) so grading is fully unit-
testable without a network, and so this module never opens a live connection
except when a user explicitly runs the CLI (default_connector).
"""
from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Optional

from .models import Certificate, EKU
from .validators.cert_checks import _name_covers
from .validators.tls_policy import _canon_cipher, _ver_tuple

MS_EDGE = "sip.g1.pstnhub.microsoft.com"
SIP_TLS_PORT = 5061


@dataclass
class HandshakeResult:
    reachable: bool
    tls_version: Optional[str] = None     # "1.2" / "1.3"
    cipher: Optional[str] = None          # negotiated cipher (OpenSSL name)
    leaf: Optional[Certificate] = None
    error: Optional[str] = None


def _parse_leaf_der(der: bytes) -> Optional[Certificate]:
    """DER leaf -> normalized Certificate, reusing the cert_inspect extractors."""
    try:
        from cryptography import x509
    except Exception:
        return None
    from .cert_inspect import _cn, _ekus, _issuer_cn, _sans
    c = x509.load_der_x509_certificate(der)
    return Certificate(
        subject_cn=_cn(c), sans=_sans(c), ekus=_ekus(c),
        not_after=c.not_valid_after_utc.date().isoformat(),
        issuer_cn=_issuer_cn(c),
    )


def default_connector(host: str, port: int = SIP_TLS_PORT,
                      timeout: float = 8.0,
                      connect_host: Optional[str] = None) -> HandshakeResult:
    """Live TLS handshake purely to INSPECT (not trust) the presented cert.

    Uses CERT_NONE on purpose: we are an outside-in scanner reading what the edge
    presents, like SSL Labs, not a peer trying to establish a trusted session.
    Only ever called from the CLI / scan server; tests inject their own connector.

    `connect_host` overrides the socket target while SNI stays `host`: the scan
    server resolves+validates the FQDN to a known-global IP first (SSRF guard),
    then connects to THAT ip so a DNS rebind cannot redirect us to an internal host.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((connect_host or host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                der = s.getpeercert(binary_form=True)
                ver = s.version()
                cipher = (s.cipher() or [None])[0]
        m = _ver_tuple(ver)
        return HandshakeResult(
            reachable=True,
            tls_version=(f"{m[0]}.{m[1]}" if m else None),
            cipher=cipher,
            leaf=_parse_leaf_der(der) if der else None,
        )
    except (OSError, ssl.SSLError, ValueError) as e:
        return HandshakeResult(reachable=False, error=f"{type(e).__name__}: {e}")


def grade_endpoint(hs: HandshakeResult, fqdn: str, ruleset: dict) -> dict:
    """Grade one handshake against the ruleset's domain-C facts. Same check IDs as
    the local validator, so the free and paid tools never disagree."""
    C = ruleset.get("C", {})
    if not hs.reachable:
        return {
            "grade": "INCONCLUSIVE", "reachable": False, "issues": [],
            "note": f"Could not reach {fqdn}:{SIP_TLS_PORT} ({hs.error}). This is "
                    "often correct hardening: an SBC may accept only Microsoft's "
                    "source ranges. Reachability is not a grade; the inside-out "
                    "config check covers what cannot be seen from here.",
        }

    issues: list[tuple[str, str, str]] = []

    req, have = _ver_tuple(C.get("tls_min_version")), _ver_tuple(hs.tls_version)
    if req and have and have < req:
        issues.append(("HIGH", "C.TLS.WEAK_VERSION",
                       f"negotiated TLS {hs.tls_version} is below the required "
                       f"{C.get('tls_min_version')}"))

    allowed = C.get("allowed_sip_cipher_suites")
    if allowed and hs.cipher:
        if _canon_cipher(hs.cipher) not in {_canon_cipher(c) for c in allowed}:
            issues.append(("MEDIUM", "C.TLS.CIPHER_NOT_ALLOWED",
                           f"negotiated cipher {hs.cipher} is not on Microsoft's "
                           "accepted list"))

    leaf = hs.leaf
    if leaf:
        if leaf.not_after:
            try:
                exp = datetime.fromisoformat(leaf.not_after).replace(tzinfo=timezone.utc)
                days = (exp - datetime.now(timezone.utc)).days
                if days < 0:
                    issues.append(("CRITICAL", "C.CERT.EXPIRY",
                                   f"leaf certificate expired ({leaf.not_after})"))
                elif days <= C.get("cert_expiry_warn_days", 30):
                    issues.append(("HIGH", "C.CERT.EXPIRY",
                                   f"leaf expires in {days}d ({leaf.not_after})"))
            except ValueError:
                pass
        if leaf.ekus and EKU.SERVER_AUTH not in leaf.ekus:
            issues.append(("HIGH", "C.CERT.EKU_NO_SERVERAUTH",
                           "leaf lacks the Server Authentication EKU (2026 requirement)"))
        names = ([leaf.subject_cn] if leaf.subject_cn else []) + list(leaf.sans or [])
        if names and fqdn and not any(_name_covers(n, fqdn) for n in names):
            issues.append(("HIGH", "C.CERT.FQDN_MISMATCH",
                           f"leaf CN/SAN does not cover {fqdn}"))

    rank = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1}
    worst = max((rank[s] for s, _, _ in issues), default=0)
    grade = {0: "A", 1: "B", 2: "C", 3: "FAIL"}[worst]
    return {
        "grade": grade, "reachable": True,
        "tls_version": hs.tls_version, "cipher": hs.cipher,
        "issues": [{"severity": s, "check_id": cid, "message": m}
                   for s, cid, m in issues],
    }


def probe(fqdn: str, ruleset: dict,
          connector: Callable[..., HandshakeResult] = default_connector,
          check_ms_edge: bool = True) -> dict:
    """Probe a customer SBC FQDN; optionally also touch Microsoft's edge as a
    live ground-truth reference (so the readiness claim is 'verified', not
    'predicted'). Pure grading; the only I/O is via `connector`."""
    out = {"fqdn": fqdn, "customer": grade_endpoint(connector(fqdn), fqdn, ruleset)}
    if check_ms_edge:
        ms = connector(MS_EDGE)
        out["microsoft_edge"] = {
            "reachable": ms.reachable,
            "tls_version": ms.tls_version,
            "cipher": ms.cipher,
            "note": ("Microsoft's Direct Routing edge is live and presenting this "
                     "TLS posture (ground-truth reference)." if ms.reachable else
                     f"reference probe to {MS_EDGE} did not complete ({ms.error})"),
        }
    return out
