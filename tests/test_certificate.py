from dataclasses import FrozenInstanceError
from datetime import UTC, datetime
from hashlib import sha256
from ipaddress import ip_address

import pytest
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import certificate as certificate_module
from certificate import (
    MAX_CERTIFICATE_DER_BYTES,
    CertificateInspectionError,
    inspect_certificate,
)


@pytest.fixture(scope="module")
def rsa_certificate() -> tuple[x509.Certificate, bytes]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "unifi.test")])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(0xABC123)
        .not_valid_before(datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC))
        .not_valid_after(datetime(2027, 1, 2, 3, 4, 5, tzinfo=UTC))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("unifi.test"),
                    x509.DNSName("controller.test"),
                    x509.IPAddress(ip_address("192.0.2.10")),
                    x509.IPAddress(ip_address("2001:db8::10")),
                ]
            ),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )
    return certificate, certificate.public_bytes(serialization.Encoding.DER)


def test_inspects_rsa_certificate(
    rsa_certificate: tuple[x509.Certificate, bytes],
) -> None:
    _, certificate_der = rsa_certificate

    info = inspect_certificate(certificate_der)

    assert info.subject == "CN=unifi.test"
    assert info.issuer == "CN=Test CA"
    assert info.serial_number == "abc123"
    assert info.public_key_algorithm == "RSA"
    assert info.public_key_size == 2048
    assert info.signature_algorithm_oid == "1.2.840.113549.1.1.11"
    assert info.signature_hash_algorithm == "sha256"
    with pytest.raises(FrozenInstanceError):
        info.subject = "changed"  # type: ignore[misc]


def test_certificate_sha256_is_deterministic(
    rsa_certificate: tuple[x509.Certificate, bytes],
) -> None:
    _, certificate_der = rsa_certificate
    expected = sha256(certificate_der).hexdigest()

    assert inspect_certificate(certificate_der).certificate_sha256 == expected
    assert inspect_certificate(certificate_der).certificate_sha256 == expected


def test_spki_sha256_is_deterministic(
    rsa_certificate: tuple[x509.Certificate, bytes],
) -> None:
    certificate, certificate_der = rsa_certificate
    spki_der = certificate.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    expected = sha256(spki_der).hexdigest()

    assert inspect_certificate(certificate_der).spki_sha256 == expected
    assert inspect_certificate(certificate_der).spki_sha256 == expected


def test_extracts_subject_alternative_names(
    rsa_certificate: tuple[x509.Certificate, bytes],
) -> None:
    _, certificate_der = rsa_certificate

    info = inspect_certificate(certificate_der)

    assert info.dns_sans == ("unifi.test", "controller.test")
    assert info.ip_sans == ("192.0.2.10", "2001:db8::10")


def test_validity_is_timezone_aware_utc(
    rsa_certificate: tuple[x509.Certificate, bytes],
) -> None:
    _, certificate_der = rsa_certificate

    info = inspect_certificate(certificate_der)

    assert info.not_valid_before == datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
    assert info.not_valid_after == datetime(2027, 1, 2, 3, 4, 5, tzinfo=UTC)
    assert info.not_valid_before.tzinfo is UTC
    assert info.not_valid_after.tzinfo is UTC


def test_extracts_subject_key_identifier(
    rsa_certificate: tuple[x509.Certificate, bytes],
) -> None:
    certificate, certificate_der = rsa_certificate
    expected = certificate.extensions.get_extension_for_class(
        x509.SubjectKeyIdentifier
    ).value.digest.hex()

    assert inspect_certificate(certificate_der).subject_key_identifier == expected


@pytest.mark.parametrize("certificate_der", [b"", b"not a DER certificate"])
def test_rejects_malformed_certificate_der(certificate_der: bytes) -> None:
    with pytest.raises(CertificateInspectionError, match="certificate DER"):
        inspect_certificate(certificate_der)


def test_rejects_certificate_der_over_size_limit() -> None:
    oversized_der = b"x" * (MAX_CERTIFICATE_DER_BYTES + 1)

    with pytest.raises(CertificateInspectionError, match="exceeds the size limit"):
        inspect_certificate(oversized_der)


def test_rejects_non_bytes_certificate_input() -> None:
    with pytest.raises(TypeError, match="certificate DER must be bytes"):
        inspect_certificate("not bytes")  # type: ignore[arg-type]


def test_preserves_intentional_certificate_inspection_error(
    monkeypatch: pytest.MonkeyPatch,
    rsa_certificate: tuple[x509.Certificate, bytes],
) -> None:
    _, certificate_der = rsa_certificate

    def reject_public_key(public_key: object) -> tuple[str, int | None]:
        raise CertificateInspectionError("unsupported certificate public-key algorithm")

    monkeypatch.setattr(certificate_module, "_public_key_info", reject_public_key)

    with pytest.raises(
        CertificateInspectionError,
        match="^unsupported certificate public-key algorithm$",
    ):
        inspect_certificate(certificate_der)


def test_reports_cryptography_unsupported_algorithm_clearly(
    monkeypatch: pytest.MonkeyPatch,
    rsa_certificate: tuple[x509.Certificate, bytes],
) -> None:
    _, certificate_der = rsa_certificate

    def reject_public_key(public_key: object) -> tuple[str, int | None]:
        raise UnsupportedAlgorithm("unsupported test algorithm")

    monkeypatch.setattr(certificate_module, "_public_key_info", reject_public_key)

    with pytest.raises(
        CertificateInspectionError,
        match="^certificate uses an unsupported algorithm$",
    ):
        inspect_certificate(certificate_der)
