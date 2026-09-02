import base64
from dataclasses import FrozenInstanceError
from hashlib import sha256
from ipaddress import ip_address

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from csr import (
    MAX_CSR_PEM_BYTES,
    ExpectedSPKIMismatchError,
    InvalidCSRSignatureError,
    InvalidSPKIFingerprintError,
    MalformedCSRError,
    inspect_csr,
    validate_csr_spki,
)


@pytest.fixture(scope="module")
def rsa_csr() -> tuple[x509.CertificateSigningRequest, bytes]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "unifi.test")])
    request = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
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
    return request, request.public_bytes(serialization.Encoding.PEM)


def test_inspects_valid_rsa_csr(
    rsa_csr: tuple[x509.CertificateSigningRequest, bytes],
) -> None:
    _, csr_pem = rsa_csr

    info = inspect_csr(csr_pem)

    assert info.subject == "CN=unifi.test"
    assert info.public_key_algorithm == "RSA"
    assert info.public_key_size == 2048
    assert info.signature_algorithm_oid == "1.2.840.113549.1.1.11"
    assert info.signature_hash_algorithm == "sha256"
    assert info.signature_valid is True
    with pytest.raises(FrozenInstanceError):
        info.subject = "changed"  # type: ignore[misc]


def test_spki_sha256_is_deterministic(
    rsa_csr: tuple[x509.CertificateSigningRequest, bytes],
) -> None:
    request, csr_pem = rsa_csr
    spki_der = request.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    expected = sha256(spki_der).hexdigest()

    assert inspect_csr(csr_pem).spki_sha256 == expected
    assert inspect_csr(csr_pem).spki_sha256 == expected


def test_extracts_requested_subject_alternative_names(
    rsa_csr: tuple[x509.CertificateSigningRequest, bytes],
) -> None:
    _, csr_pem = rsa_csr

    info = inspect_csr(csr_pem)

    assert info.dns_sans == ("unifi.test", "controller.test")
    assert info.ip_sans == ("192.0.2.10", "2001:db8::10")


def test_extracts_requested_subject_key_identifier(
    rsa_csr: tuple[x509.CertificateSigningRequest, bytes],
) -> None:
    request, csr_pem = rsa_csr
    expected = request.extensions.get_extension_for_class(
        x509.SubjectKeyIdentifier
    ).value.digest.hex()

    assert inspect_csr(csr_pem).subject_key_identifier == expected


def test_accepts_keytool_new_certificate_request_pem_label(
    rsa_csr: tuple[x509.CertificateSigningRequest, bytes],
) -> None:
    _, csr_pem = rsa_csr
    keytool_pem = csr_pem.replace(
        b"CERTIFICATE REQUEST",
        b"NEW CERTIFICATE REQUEST",
    )

    assert inspect_csr(keytool_pem).signature_valid is True


@pytest.mark.parametrize("csr_pem", [b"", b"not a PEM CSR"])
def test_rejects_malformed_csr_pem(csr_pem: bytes) -> None:
    with pytest.raises(MalformedCSRError, match="CSR PEM"):
        inspect_csr(csr_pem)


def test_rejects_non_bytes_csr_input() -> None:
    with pytest.raises(TypeError, match="CSR PEM must be bytes"):
        inspect_csr("not bytes")  # type: ignore[arg-type]


def test_rejects_oversized_csr_input() -> None:
    oversized_pem = b"x" * (MAX_CSR_PEM_BYTES + 1)

    with pytest.raises(MalformedCSRError, match="exceeds the size limit"):
        inspect_csr(oversized_pem)


@pytest.mark.parametrize("extra", [b"unexpected output\n", b"second payload\n"])
def test_rejects_non_whitespace_outside_single_csr_pem(
    rsa_csr: tuple[x509.CertificateSigningRequest, bytes],
    extra: bytes,
) -> None:
    _, csr_pem = rsa_csr
    input_pem = extra + csr_pem if extra.startswith(b"unexpected") else csr_pem + extra

    with pytest.raises(MalformedCSRError, match="invalid CSR PEM"):
        inspect_csr(input_pem)


def test_rejects_multiple_csr_pem_blocks(
    rsa_csr: tuple[x509.CertificateSigningRequest, bytes],
) -> None:
    _, csr_pem = rsa_csr

    with pytest.raises(MalformedCSRError, match="invalid CSR PEM"):
        inspect_csr(csr_pem + csr_pem)


def test_rejects_structurally_valid_csr_with_corrupted_signature(
    rsa_csr: tuple[x509.CertificateSigningRequest, bytes],
) -> None:
    request, _ = rsa_csr
    corrupted_der = bytearray(request.public_bytes(serialization.Encoding.DER))
    corrupted_der[-1] ^= 1
    encoded = base64.b64encode(corrupted_der)
    corrupted_pem = (
        b"-----BEGIN CERTIFICATE REQUEST-----\n"
        + b"\n".join(
            encoded[index : index + 64] for index in range(0, len(encoded), 64)
        )
        + b"\n-----END CERTIFICATE REQUEST-----\n"
    )

    with pytest.raises(InvalidCSRSignatureError, match="proof-of-possession"):
        inspect_csr(corrupted_pem)


@pytest.mark.parametrize(
    "fingerprint",
    ["", "a" * 63, "a" * 65, "g" * 64, "aa:" * 31 + "aa", " a" * 32],
)
def test_rejects_malformed_expected_spki_fingerprint(
    rsa_csr: tuple[x509.CertificateSigningRequest, bytes],
    fingerprint: str,
) -> None:
    _, csr_pem = rsa_csr

    with pytest.raises(InvalidSPKIFingerprintError, match="64 hexadecimal"):
        validate_csr_spki(inspect_csr(csr_pem), fingerprint)


def test_rejects_non_text_expected_spki_fingerprint(
    rsa_csr: tuple[x509.CertificateSigningRequest, bytes],
) -> None:
    _, csr_pem = rsa_csr

    with pytest.raises(TypeError, match="expected SPKI SHA-256 must be text"):
        validate_csr_spki(inspect_csr(csr_pem), b"0" * 64)  # type: ignore[arg-type]


def test_rejects_expected_spki_mismatch(
    rsa_csr: tuple[x509.CertificateSigningRequest, bytes],
) -> None:
    _, csr_pem = rsa_csr

    with pytest.raises(ExpectedSPKIMismatchError, match="does not match"):
        validate_csr_spki(inspect_csr(csr_pem), "0" * 64)


def test_accepts_matching_expected_spki_in_either_hex_case(
    rsa_csr: tuple[x509.CertificateSigningRequest, bytes],
) -> None:
    _, csr_pem = rsa_csr
    info = inspect_csr(csr_pem)

    assert validate_csr_spki(info, info.spki_sha256) is None
    assert validate_csr_spki(info, info.spki_sha256.upper()) is None
