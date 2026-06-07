"""
Real certificate inspection (the deep pass for domain C).

Turns actual PEM/DER material into the normalized Certificate model:
extracts CN, SANs, EKUs, validity, issuer, and attempts a local chain build.
Runs ONLY on cert files present inside the trust boundary; no network, no
revocation calls (OCSP/CRL would be network and are out of the local-first path).

Falls back gracefully: if `cryptography` is unavailable or a file can't be
parsed, the caller keeps the config-declared values instead of crashing.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from .models import EKU, Certificate

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, NameOID
    _AVAILABLE = True
except Exception:  # pragma: no cover
    _AVAILABLE = False


def available() -> bool:
    return _AVAILABLE


def _load_all(pem_bytes: bytes):
    """Load one or more concatenated PEM certs (leaf first, by convention)."""
    try:
        return x509.load_pem_x509_certificates(pem_bytes)
    except AttributeError:
        # older cryptography: load just the first
        return [x509.load_pem_x509_certificate(pem_bytes)]


def _cn(cert) -> Optional[str]:
    attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return attrs[0].value if attrs else None


def _issuer_cn(cert) -> Optional[str]:
    attrs = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
    return attrs[0].value if attrs else None


def _sans(cert) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        return list(ext.value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        return []


def _ekus(cert) -> list[EKU]:
    out: list[EKU] = []
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
    except x509.ExtensionNotFound:
        return out
    for oid in ext.value:
        if oid == ExtendedKeyUsageOID.SERVER_AUTH:
            out.append(EKU.SERVER_AUTH)
        elif oid == ExtendedKeyUsageOID.CLIENT_AUTH:
            out.append(EKU.CLIENT_AUTH)
    return out


def _chain_complete(certs) -> bool:
    """
    Best-effort local chain check: can we walk leaf -> ... -> self-signed root
    using only the certs supplied in the bundle? (Trust-anchor validation against
    the OS/SBC store is a separate step; this just checks the chain isn't broken.)
    """
    if not certs:
        return False
    by_subject = {c.subject.rfc4514_string(): c for c in certs}
    current = certs[0]
    seen = set()
    while True:
        subj = current.subject.rfc4514_string()
        iss = current.issuer.rfc4514_string()
        if subj == iss:
            return True  # reached a self-signed root within the bundle
        if iss in seen or iss not in by_subject:
            return False  # missing intermediate / loop
        seen.add(iss)
        current = by_subject[iss]


def inspect_file(path: str) -> Optional[Certificate]:
    """Return a populated Certificate from a PEM file, or None if unparseable."""
    if not _AVAILABLE:
        return None
    p = Path(path)
    if not p.exists():
        return None
    try:
        certs = _load_all(p.read_bytes())
    except Exception:
        return None
    if not certs:
        return None
    leaf = certs[0]
    return Certificate(
        subject_cn=_cn(leaf),
        sans=_sans(leaf),
        ekus=_ekus(leaf),
        not_after=leaf.not_valid_after_utc.date().isoformat(),
        issuer_cn=_issuer_cn(leaf),
        chain_complete=_chain_complete(certs),
        source_file=str(p),
    )


def verify_chain(path: str) -> Optional[dict]:
    """Real trust-anchor analysis of a PEM that may hold a full chain.

    Verifies the signature of each cert against its issuer (real PKI, not just
    name matching), walks to a self-signed root, and returns:

      {leaf_self_signed, signatures_valid, reached_root, terminal_sha1, length}

    terminal_sha1 is the SHA-1 fingerprint (hex, upper) of the self-signed root
    the chain terminates at, or None if it never reaches one. Returns None if
    cryptography is unavailable or the file can't be read.
    """
    if not _AVAILABLE:
        return None
    p = Path(path)
    if not p.exists():
        return None
    try:
        certs = _load_all(p.read_bytes())
    except Exception:
        return None
    if not certs:
        return None

    by_subject = {c.subject.rfc4514_string(): c for c in certs}
    leaf = certs[0]
    leaf_self_signed = leaf.subject.rfc4514_string() == leaf.issuer.rfc4514_string()

    signatures_valid = True
    reached_root = False
    terminal_sha1 = None
    seen = set()
    cur = leaf
    while True:
        subj = cur.subject.rfc4514_string()
        iss = cur.issuer.rfc4514_string()
        if subj == iss:                          # self-signed root reached
            # verify the root's own signature too
            issuer = cur
            reached_root = True
            terminal_sha1 = cur.fingerprint(hashes.SHA1()).hex().upper()
        else:
            issuer = by_subject.get(iss)
            if issuer is None:
                break                            # intermediate missing -> incomplete
        try:
            cur.verify_directly_issued_by(issuer)
        except Exception:
            signatures_valid = False
            break
        if reached_root or iss in seen:
            break
        seen.add(iss)
        cur = issuer

    return {
        "leaf_self_signed": leaf_self_signed,
        "signatures_valid": signatures_valid,
        "reached_root": reached_root,
        "terminal_sha1": terminal_sha1,
        "length": len(certs),
    }
