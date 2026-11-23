"""Tests for harness.py (slice S14).

PEM/DER throwaway certificate generation via cryptography x509. Never
hand-parsed PEM. Certificates are valid for 7 days only — throwaway test
material, never production.
"""

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID  # noqa: F401
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from pqblocks_tlsfuzz.harness import (
    VALIDITY_DAYS,
    generate_harness_keypair,
    generate_throwaway_ca,
    generate_throwaway_leaf,
    cert_to_pem,
    cert_to_der,
    load_cert_from_pem,
    load_cert_from_der,
    pem_der_roundtrip,
    cert_fingerprint_sha256,
    cert_validity_window,
    is_cert_expired,
    write_cert_files,
    verify_leaf_signed_by_ca,
    HarnessError,
)
from pqblocks_tlsfuzz.errors import PqTlsFuzzError


class TestGenerateThrowawayCA:
    def test_generate_ca_returns_cert_and_key(self):
        cert, key = generate_throwaway_ca()
        assert isinstance(cert, x509.Certificate)
        assert isinstance(key, rsa.RSAPrivateKey)

    def test_ca_is_self_signed(self):
        cert, _ = generate_throwaway_ca()
        assert cert.issuer == cert.subject

    def test_ca_has_ca_basic_constraints(self):
        cert, _ = generate_throwaway_ca()
        ext = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert ext.value.ca is True

    def test_ca_validity_window_is_7_days(self):
        cert, _ = generate_throwaway_ca(validity_days=7)
        before, after = cert_validity_window(cert)
        delta = after - before
        assert delta == timedelta(days=7)

    def test_ca_common_name_in_subject(self):
        cert, _ = generate_throwaway_ca(common_name="test-ca")
        cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0]
        assert cn.value == "test-ca"


class TestGenerateThrowawayLeaf:
    def test_generate_leaf_returns_cert_and_key(self):
        ca_cert, ca_key = generate_throwaway_ca()
        cert, key = generate_throwaway_leaf(ca_cert, ca_key)
        assert isinstance(cert, x509.Certificate)
        assert isinstance(key, rsa.RSAPrivateKey)

    def test_leaf_issued_by_ca(self):
        ca_cert, ca_key = generate_throwaway_ca()
        cert, _ = generate_throwaway_leaf(ca_cert, ca_key)
        assert cert.issuer == ca_cert.subject

    def test_leaf_not_ca(self):
        ca_cert, ca_key = generate_throwaway_ca()
        cert, _ = generate_throwaway_leaf(ca_cert, ca_key)
        ext = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert ext.value.ca is False

    def test_leaf_has_san_dns_names(self):
        ca_cert, ca_key = generate_throwaway_ca()
        cert, _ = generate_throwaway_leaf(
            ca_cert, ca_key, san_dns_names=("localhost", "example.test")
        )
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        names = san.value.get_values_for_type(x509.DNSName)
        assert "localhost" in names
        assert "example.test" in names

    def test_leaf_eku_sanity_server_auth_only(self):
        """EKU sanity: the leaf must carry id-kp-serverAuth and NOT clientAuth."""
        ca_cert, ca_key = generate_throwaway_ca()
        cert, _ = generate_throwaway_leaf(ca_cert, ca_key)
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        assert ExtendedKeyUsageOID.SERVER_AUTH in eku.value
        assert ExtendedKeyUsageOID.CLIENT_AUTH not in eku.value

    def test_verify_leaf_signed_by_ca_returns_true(self):
        ca_cert, ca_key = generate_throwaway_ca()
        cert, _ = generate_throwaway_leaf(ca_cert, ca_key)
        assert verify_leaf_signed_by_ca(cert, ca_cert) is True

    def test_verify_leaf_signed_by_wrong_ca_returns_false(self):
        ca_cert_a, _ = generate_throwaway_ca(common_name="ca-a")
        ca_cert_b, _ = generate_throwaway_ca(common_name="ca-b")
        cert, _ = generate_throwaway_leaf(ca_cert_a, ca_cert_a_private_key := None) if False else (None, None)
        # Re-generate properly
        ca_cert_a, ca_key_a = generate_throwaway_ca(common_name="ca-a")
        cert, _ = generate_throwaway_leaf(ca_cert_a, ca_key_a)
        assert verify_leaf_signed_by_ca(cert, ca_cert_b) is False


class TestPEMDERRoundtrip:
    def test_cert_to_pem_returns_bytes(self):
        ca_cert, _ = generate_throwaway_ca()
        pem = cert_to_pem(ca_cert)
        assert isinstance(pem, bytes)
        assert pem.startswith(b"-----BEGIN CERTIFICATE-----")
        assert pem.endswith(b"-----END CERTIFICATE-----\n")

    def test_cert_to_der_returns_bytes(self):
        ca_cert, _ = generate_throwaway_ca()
        der = cert_to_der(ca_cert)
        assert isinstance(der, bytes)
        assert der.startswith(b"\x30")  # DER SEQUENCE tag

    def test_pem_der_roundtrip_is_byte_identical(self):
        ca_cert, _ = generate_throwaway_ca()
        re_parsed = pem_der_roundtrip(ca_cert)
        assert cert_to_pem(re_parsed) == cert_to_pem(ca_cert)

    def test_load_cert_from_pem_roundtrips(self):
        ca_cert, _ = generate_throwaway_ca()
        pem = cert_to_pem(ca_cert)
        loaded = load_cert_from_pem(pem)
        assert cert_to_pem(loaded) == pem

    def test_load_cert_from_der_roundtrips(self):
        ca_cert, _ = generate_throwaway_ca()
        der = cert_to_der(ca_cert)
        loaded = load_cert_from_der(der)
        assert cert_to_der(loaded) == der

    def test_load_bad_pem_raises_harness_error(self):
        with pytest.raises(HarnessError):
            load_cert_from_pem(b"not a certificate")

    def test_load_bad_der_raises_harness_error(self):
        with pytest.raises(HarnessError):
            load_cert_from_der(b"\x00\x01\x02")


class TestCertFingerprint:
    def test_fingerprint_is_hex_string(self):
        ca_cert, _ = generate_throwaway_ca()
        fp = cert_fingerprint_sha256(ca_cert)
        assert isinstance(fp, str)
        assert len(fp) == 64
        int(fp, 16)  # must be valid hex

    def test_fingerprint_deterministic(self):
        ca_cert, _ = generate_throwaway_ca()
        fp1 = cert_fingerprint_sha256(ca_cert)
        fp2 = cert_fingerprint_sha256(ca_cert)
        assert fp1 == fp2


class TestCertValidity:
    def test_cert_not_expired_when_fresh(self):
        ca_cert, _ = generate_throwaway_ca(validity_days=7)
        assert is_cert_expired(ca_cert) is False

    def test_cert_validity_window_utc(self):
        ca_cert, _ = generate_throwaway_ca()
        before, after = cert_validity_window(ca_cert)
        assert before.tzinfo is not None
        assert after.tzinfo is not None


class TestWriteCertFiles:
    def test_write_cert_files_creates_pem_files(self, tmp_path):
        ca_cert, ca_key = generate_throwaway_ca()
        cert_path = tmp_path / "ca.pem"
        key_path = tmp_path / "ca.key"
        write_cert_files(ca_cert, ca_key, cert_path, key_path, pem_only=True)
        assert cert_path.exists()
        assert key_path.exists()
        assert cert_path.read_bytes().startswith(b"-----BEGIN CERTIFICATE-----")
        assert key_path.read_bytes().startswith(b"-----BEGIN PRIVATE KEY-----")

    def test_write_cert_files_creates_der_siblings(self, tmp_path):
        ca_cert, ca_key = generate_throwaway_ca()
        cert_path = tmp_path / "ca.pem"
        key_path = tmp_path / "ca.key"
        write_cert_files(ca_cert, ca_key, cert_path, key_path, pem_only=False)
        assert (tmp_path / "ca.der").exists()
        assert (tmp_path / "ca.key.der").exists()

    def test_write_cert_files_creates_parent_dirs(self, tmp_path):
        ca_cert, ca_key = generate_throwaway_ca()
        cert_path = tmp_path / "sub" / "dir" / "ca.pem"
        key_path = tmp_path / "sub" / "dir" / "ca.key"
        write_cert_files(ca_cert, ca_key, cert_path, key_path, pem_only=True)
        assert cert_path.exists()
        assert key_path.exists()


class TestGenerateHarnessKeypair:
    def test_generate_harness_keypair_writes_all_files(self, tmp_path):
        paths = generate_harness_keypair(tmp_path)
        expected = {
            "ca_cert", "ca_key", "ca_cert_der", "ca_key_der",
            "leaf_cert", "leaf_key", "leaf_cert_der", "leaf_key_der",
        }
        assert set(paths.keys()) == expected
        for name, path in paths.items():
            assert path.exists(), f"{name} missing at {path}"

    def test_generate_harness_keypair_leaf_signed_by_ca(self, tmp_path):
        paths = generate_harness_keypair(tmp_path)
        ca_cert = load_cert_from_pem(paths["ca_cert"].read_bytes())
        leaf_cert = load_cert_from_pem(paths["leaf_cert"].read_bytes())
        assert verify_leaf_signed_by_ca(leaf_cert, ca_cert) is True

    def test_generate_harness_keypair_creates_dir(self, tmp_path):
        new_dir = tmp_path / "new_subdir"
        paths = generate_harness_keypair(new_dir)
        assert new_dir.exists()
        assert paths["ca_cert"].exists()