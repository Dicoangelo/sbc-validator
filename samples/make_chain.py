"""
Generate a real CA -> intermediate -> leaf certificate chain fixture, so the
trust-anchor chain validation can be tested against an actual signed chain (not a
self-signed stub). Writes:

  samples/chain_fullchain.pem   leaf + intermediate + root (leaf first)
  samples/chain_root.pem        the self-signed root only (its SHA-1 is the anchor)

    python samples/make_chain.py
"""
from __future__ import annotations

import datetime
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

HERE = Path(__file__).resolve().parent
NB = datetime.datetime(2026, 1, 1)
NA = datetime.datetime(2028, 1, 1)


def _key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _ca(subject, issuer_name, issuer_key, subject_key, path_len):
    return (x509.CertificateBuilder()
            .subject_name(_name(subject)).issuer_name(issuer_name)
            .public_key(subject_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(NB).not_valid_after(NA)
            .add_extension(x509.BasicConstraints(ca=True, path_length=path_len), critical=True)
            .sign(issuer_key, hashes.SHA256()))


def main():
    root_key, int_key, leaf_key = _key(), _key(), _key()

    root = _ca("SBC Test Root CA", _name("SBC Test Root CA"), root_key, root_key, 1)
    inter = _ca("SBC Test Intermediate CA", root.subject, root_key, int_key, 0)

    cn = "sbc01.contoso.com"
    leaf = (x509.CertificateBuilder()
            .subject_name(_name(cn)).issuer_name(inter.subject)
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(NB).not_valid_after(NA)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(int_key, hashes.SHA256()))

    def pem(c):
        return c.public_bytes(serialization.Encoding.PEM)

    (HERE / "chain_fullchain.pem").write_bytes(pem(leaf) + pem(inter) + pem(root))
    (HERE / "chain_root.pem").write_bytes(pem(root))
    sha1 = root.fingerprint(hashes.SHA1()).hex().upper()
    print("wrote chain_fullchain.pem + chain_root.pem")
    print("root SHA-1:", sha1)


if __name__ == "__main__":
    main()
