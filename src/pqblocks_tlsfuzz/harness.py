"""PEM/DER throwaway certificate harness (slice S14).

Generates ephemeral CA + leaf certificates via cryptography x509 (never
hand-parsed PEM). Consumed by the S22 interop harness to stand up a local
reference TLS endpoint. Certificates are valid for 7 days only — throwaway,
never for production use.
"""

from __future__ import annotations

import hashlib
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.x509.oid import NameOID, ExtensionOID, ExtendedKeyUsageOID  # noqa: F401

from pqblocks_tlsfuzz.errors import PqTlsFuzzError


class HarnessError(PqTlsFuzzError):
    """Raised when certificate generation or PEM/DER round-trip fails."""


# Validity window for throwaway harness certs: 7 days (never production).
VALIDITY_DAYS = 7


def _utc_now() -> datetime:
    """Return current UTC time with microsecond precision, always tz-aware."""
    return datetime.now(timezone.utc).replace(microsecond=0)


def generate_rsa_keypair(key_size: int = 2048) -> rsa.RSAPrivateKey:
    """Generate an RSA keypair for the throwaway CA/leaf (not production grade)."""
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size)


def generate_ec_keypair(curve: Any = ec.SECP256R1()) -> ec.EllipticCurvePrivateKey:
    """Generate an elliptic-curve keypair for the throwaway CA/leaf."""
    return ec.generate_private_key(curve)


def _subject_issuer_name(common_name: str) -> x509.Name:
    """Build an X.509 subject/issuer name from a common name."""
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "XX"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Harness"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Localhost"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "pqblocks-tlsfuzz-harness"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])


def generate_throwaway_ca(
    common_name: str = "pqblocks-tlsfuzz-throwaway-ca",
    key_size: int = 2048,
    validity_days: int = VALIDITY_DAYS,
) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    """Generate a self-signed throwaway root CA certificate and private key.

    Returns ``(certificate, private_key)``. The cert is self-signed with
    basicConstraints CA:TRUE and a 7-day validity window by default. Not for
    production use — ephemeral test material only.
    """
    key = generate_rsa_keypair(key_size)
    now = _utc_now()
    not_after = now + timedelta(days=validity_days)

    builder = (
        x509.CertificateBuilder()
        .subject_name(_subject_issuer_name(common_name))
        .issuer_name(_subject_issuer_name(common_name))
        .public_key(key.public_key())
        .serial_number(int.from_bytes(os.urandom(16), "big"))
        .not_valid_before(now)
        .not_valid_after(not_after)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
    )
    cert = builder.sign(private_key=key, algorithm=hashes.SHA256())
    return cert, key


def generate_throwaway_leaf(
    ca_cert: x509.Certificate,
    ca_key: rsa.RSAPrivateKey,
    common_name: str = "localhost",
    san_dns_names: tuple[str, ...] = ("localhost",),
    san_ip_addresses: tuple[str, ...] = ("127.0.0.1",),
    key_size: int = 2048,
    validity_days: int = VALIDITY_DAYS,
) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    """Generate a leaf certificate signed by the throwaway CA.

    Returns ``(certificate, private_key)``. Includes SAN DNS/IP entries so
    the cert validates against localhost endpoints. Not for production use.
    """
    key = generate_rsa_keypair(key_size)
    now = _utc_now()
    not_after = now + timedelta(days=validity_days)

    builder = (
        x509.CertificateBuilder()
        .subject_name(_subject_issuer_name(common_name))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(int.from_bytes(os.urandom(16), "big"))
        .not_valid_before(now)
        .not_valid_after(not_after)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
            critical=False,
        )
        .add_extension(
            # EKU sanity: leaf is a TLS server certificate — serverAuth only.
            x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
    )

    # Build SAN extension from DNS names and IP addresses.
    san_entries: list[Any] = []
    for dns in san_dns_names:
        san_entries.append(x509.DNSName(dns))
    for ip_str in san_ip_addresses:
        import ipaddress
        san_entries.append(x509.IPAddress(ipaddress.ip_address(ip_str)))

    if san_entries:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(san_entries),
            critical=False,
        )

    cert = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())
    return cert, key


def cert_to_pem(cert: x509.Certificate) -> bytes:
    """Serialize a certificate to PEM-encoded bytes."""
    return cert.public_bytes(serialization.Encoding.PEM)


def cert_to_der(cert: x509.Certificate) -> bytes:
    """Serialize a certificate to DER-encoded bytes."""
    return cert.public_bytes(serialization.Encoding.DER)


def private_key_to_pem(key: Any, encryption: bool = False) -> bytes:
    """Serialize a private key to PEM-encoded bytes (unencrypted by default)."""
    enc: Any = serialization.NoEncryption()
    if encryption:
        enc = serialization.BestAvailableEncryption(b"harness-throwaway")
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc,
    )


def load_cert_from_pem(pem_bytes: bytes) -> x509.Certificate:
    """Load a certificate from PEM-encoded bytes. Raises HarnessError on bad input."""
    try:
        return x509.load_pem_x509_certificate(pem_bytes)
    except Exception as exc:  # pragma: no cover - cryptography raises on bad PEM
        raise HarnessError(f"cannot load PEM certificate: {exc}") from exc


def load_cert_from_der(der_bytes: bytes) -> x509.Certificate:
    """Load a certificate from DER-encoded bytes. Raises HarnessError on bad input."""
    try:
        return x509.load_der_x509_certificate(der_bytes)
    except Exception as exc:  # pragma: no cover - cryptography raises on bad DER
        raise HarnessError(f"cannot load DER certificate: {exc}") from exc


def pem_der_roundtrip(cert: x509.Certificate) -> x509.Certificate:
    """PEM -> DER -> PEM round-trip, returning the re-parsed certificate.

    Asserts byte-identity through the DER intermediate: the re-parsed PEM
    must equal the original PEM exactly. Raises HarnessError on mismatch.
    """
    pem = cert_to_pem(cert)
    der = cert_to_der(cert)
    re_parsed = load_cert_from_der(der)
    re_pem = cert_to_pem(re_parsed)
    if re_pem != pem:
        raise HarnessError(
            f"PEM/DER roundtrip mismatch: original {len(pem)} bytes, "
            f"re-parsed {len(re_pem)} bytes"
        )
    return re_parsed


def cert_fingerprint_sha256(cert: x509.Certificate) -> str:
    """Return the SHA-256 fingerprint of a certificate as a lowercase hex string."""
    der = cert_to_der(cert)
    return hashlib.sha256(der).hexdigest()


def cert_validity_window(cert: x509.Certificate) -> tuple[datetime, datetime]:
    """Return (not_before, not_after) as timezone-aware UTC datetimes."""
    return cert.not_valid_before_utc, cert.not_valid_after_utc


def is_cert_expired(cert: x509.Certificate) -> bool:
    """Return True if the certificate's not_after is in the past (UTC)."""
    return cert.not_valid_after_utc < _utc_now()


def write_cert_files(
    cert: x509.Certificate,
    key: Any,
    cert_path: Path,
    key_path: Path,
    *,
    pem_only: bool = True,
) -> None:
    """Write certificate and private key to disk as PEM files.

    If ``pem_only`` is False, also writes DER siblings with .der extension.
    Parent directories are created if missing.
    """
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.parent.mkdir(parents=True, exist_ok=True)

    cert_path.write_bytes(cert_to_pem(cert))
    key_path.write_bytes(private_key_to_pem(key))

    if not pem_only:
        cert_der = cert_path.with_suffix(".der")
        key_der = key_path.with_name(key_path.name + ".der")
        cert_der.write_bytes(cert_to_der(cert))
        key_der.write_bytes(key.private_bytes(encoding=serialization.Encoding.DER, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()))


def generate_harness_keypair(
    dir_path: Path | str,
    common_name: str = "pqblocks-tlsfuzz-harness",
) -> dict[str, Path]:
    """Generate a complete throwaway CA + leaf keypair and write to disk.

    Writes ca.pem, ca.key, leaf.pem, leaf.key (and .der variants) into
    ``dir_path``. Returns a dict mapping names to Path objects.
    """
    root = Path(dir_path)
    root.mkdir(parents=True, exist_ok=True)

    ca_cert, ca_key = generate_throwaway_ca(common_name=f"{common_name}-ca")
    leaf_cert, leaf_key = generate_throwaway_leaf(
        ca_cert, ca_key, common_name=common_name,
    )

    paths: dict[str, Path] = {}
    write_cert_files(ca_cert, ca_key, root / "ca.pem", root / "ca.key", pem_only=False)
    write_cert_files(leaf_cert, leaf_key, root / "leaf.pem", root / "leaf.key", pem_only=False)

    paths["ca_cert"] = root / "ca.pem"
    paths["ca_key"] = root / "ca.key"
    paths["ca_cert_der"] = root / "ca.der"
    paths["ca_key_der"] = root / "ca.key.der"
    paths["leaf_cert"] = root / "leaf.pem"
    paths["leaf_key"] = root / "leaf.key"
    paths["leaf_cert_der"] = root / "leaf.der"
    paths["leaf_key_der"] = root / "leaf.key.der"
    return paths


def verify_leaf_signed_by_ca(leaf_cert: x509.Certificate, ca_cert: x509.Certificate) -> bool:
    """Verify that ``leaf_cert`` was signed by ``ca_cert``.

    Checks issuer name match and signature verification using the CA's public
    key. Returns True only if both checks pass.
    """
    if leaf_cert.issuer != ca_cert.subject:
        return False
    try:
        ca_pub = ca_cert.public_key()
        if isinstance(ca_pub, ec.EllipticCurvePublicKey):
            ca_pub.verify(
                leaf_cert.signature,
                leaf_cert.tbs_certificate_bytes,
                ec.ECDSA(leaf_cert.signature_hash_algorithm)
            )
        elif isinstance(ca_pub, rsa.RSAPublicKey):
            ca_pub.verify(
                leaf_cert.signature,
                leaf_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                leaf_cert.signature_hash_algorithm
            )
    except Exception:
        return False
    return True