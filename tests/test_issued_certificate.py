from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from certificate import (
    MAX_ISSUED_CERTIFICATE_BYTES,
    IssuedCertificateValidationError,
    validate_issued_certificate,
)
from csr import CSRInfo, inspect_csr

NOW = datetime(2026, 1, 1, tzinfo=UTC)


@dataclass(frozen=True)
class CertificateMaterial:
    leaf_key: rsa.RSAPrivateKey
    csr_info: CSRInfo
    ca_key: rsa.RSAPrivateKey
    ca_certificate: x509.Certificate


@pytest.fixture(scope="module")
def material() -> CertificateMaterial:
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "unifi.test")])
        )
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
        .sign(leaf_key, hashes.SHA256())
    )
    csr_info = inspect_csr(csr.public_bytes(serialization.Encoding.PEM))

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Internal CA")])
    ca_certificate = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=365))
        .not_valid_after(NOW + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
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
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return CertificateMaterial(leaf_key, csr_info, ca_key, ca_certificate)


def _issued_certificate(
    material: CertificateMaterial,
    *,
    public_key=None,
    subject: x509.Name | None = None,
    dns_sans: tuple[str, ...] = ("unifi.test", "controller.test"),
    ip_sans: tuple[str, ...] = ("192.0.2.10", "2001:db8::10"),
    extra_sans: tuple[x509.GeneralName, ...] = (),
    basic_constraints: bool | None = False,
    eku: tuple[x509.ObjectIdentifier, ...] | None = (ExtendedKeyUsageOID.SERVER_AUTH,),
    key_usage: str | None = "server",
    not_before: datetime = NOW - timedelta(minutes=1),
    not_after: datetime = NOW - timedelta(minutes=1) + timedelta(days=30),
) -> x509.Certificate:
    builder = (
        x509.CertificateBuilder()
        .subject_name(
            subject
            or x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "unifi.test")])
        )
        .issuer_name(material.ca_certificate.subject)
        .public_key(public_key or material.leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    *(x509.DNSName(name) for name in dns_sans),
                    *(x509.IPAddress(ip_address(address)) for address in ip_sans),
                    *extra_sans,
                ]
            ),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                material.ca_key.public_key()
            ),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(
                public_key or material.leaf_key.public_key()
            ),
            critical=False,
        )
    )
    if basic_constraints is not None:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=basic_constraints, path_length=None),
            critical=True,
        )
    if eku is not None:
        builder = builder.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
    if key_usage is not None:
        permits_digital_signature = key_usage in {"digital-signature", "server"}
        permits_key_encipherment = key_usage in {"key-encipherment", "server"}
        permits_ca = key_usage == "ca"
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=permits_digital_signature,
                content_commitment=False,
                key_encipherment=permits_key_encipherment,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=permits_ca,
                crl_sign=permits_ca,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    return builder.sign(material.ca_key, hashes.SHA256())


def _pem(certificate: x509.Certificate) -> bytes:
    return certificate.public_bytes(serialization.Encoding.PEM)


def _ca_pem(material: CertificateMaterial) -> bytes:
    return _pem(material.ca_certificate)


def _validate(
    material: CertificateMaterial,
    certificate: x509.Certificate,
    *,
    csr_info: CSRInfo | None = None,
    trusted_ca_data: bytes | None = None,
):
    return validate_issued_certificate(
        _pem(certificate),
        csr_info or material.csr_info,
        trusted_ca_data=trusted_ca_data or _ca_pem(material),
        lifetime_days=30,
        now=NOW,
    )


def test_accepts_valid_server_leaf_and_matching_configured_ca(material) -> None:
    certificate = _issued_certificate(material)

    info = _validate(material, certificate)

    assert info.subject == material.csr_info.subject
    assert info.spki_sha256 == material.csr_info.spki_sha256
    assert info.dns_sans == material.csr_info.dns_sans
    assert info.ip_sans == material.csr_info.ip_sans


def test_accepts_der_and_explicitly_allows_absent_key_usage(material) -> None:
    certificate = _issued_certificate(material, key_usage=None)

    info = validate_issued_certificate(
        certificate.public_bytes(serialization.Encoding.DER),
        material.csr_info,
        trusted_ca_data=_ca_pem(material),
        lifetime_days=30,
        now=NOW,
    )

    assert info.spki_sha256 == material.csr_info.spki_sha256


@pytest.mark.parametrize("key_usage", ["digital-signature", "server"])
def test_accepts_required_rsa_server_key_usages(material, key_usage) -> None:
    certificate = _issued_certificate(material, key_usage=key_usage)

    info = _validate(material, certificate)

    assert info.spki_sha256 == material.csr_info.spki_sha256


@pytest.mark.parametrize("address", ["192.0.2.10", "2001:db8::10"])
def test_accepts_exact_ip_only_server_identity(material, address) -> None:
    csr_info = replace(material.csr_info, dns_sans=(), ip_sans=(address,))
    certificate = _issued_certificate(material, dns_sans=(), ip_sans=(address,))

    info = _validate(material, certificate, csr_info=csr_info)

    assert info.ip_sans == (address,)


def test_rejects_spki_mismatch(material) -> None:
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    with pytest.raises(IssuedCertificateValidationError, match="public key"):
        _validate(
            material,
            _issued_certificate(material, public_key=other_key.public_key()),
        )


def test_rejects_subject_mismatch(material) -> None:
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "other.test")])

    with pytest.raises(IssuedCertificateValidationError, match="subject"):
        _validate(material, _issued_certificate(material, subject=subject))


@pytest.mark.parametrize(
    ("dns_sans", "ip_sans", "message"),
    [
        (("unifi.test",), ("192.0.2.10", "2001:db8::10"), "DNS SAN"),
        (
            ("unifi.test", "controller.test", "extra.test"),
            ("192.0.2.10", "2001:db8::10"),
            "DNS SAN",
        ),
        (
            ("unifi.test", "controller.test"),
            ("2001:db8::10",),
            "IP SAN",
        ),
        (
            ("unifi.test", "controller.test"),
            ("192.0.2.10",),
            "IP SAN",
        ),
    ],
)
def test_rejects_dns_ipv4_and_ipv6_san_mismatch(
    material, dns_sans, ip_sans, message
) -> None:
    with pytest.raises(IssuedCertificateValidationError, match=message):
        _validate(
            material,
            _issued_certificate(material, dns_sans=dns_sans, ip_sans=ip_sans),
        )


def test_rejects_unsupported_san_identity_type(material) -> None:
    with pytest.raises(IssuedCertificateValidationError, match="unsupported"):
        _validate(
            material,
            _issued_certificate(
                material,
                extra_sans=(x509.RFC822Name("operator@example.test"),),
            ),
        )


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"basic_constraints": None}, "missing Basic Constraints"),
        ({"basic_constraints": True}, "CA to FALSE"),
        ({"eku": None}, "missing Extended Key Usage"),
        ({"eku": (ExtendedKeyUsageOID.CLIENT_AUTH,)}, "only serverAuth"),
        (
            {
                "eku": (
                    ExtendedKeyUsageOID.SERVER_AUTH,
                    ExtendedKeyUsageOID.CLIENT_AUTH,
                )
            },
            "only serverAuth",
        ),
        ({"key_usage": "ca"}, "CA signing"),
        ({"key_usage": "key-encipherment"}, "digitalSignature"),
        ({"key_usage": "neither"}, "digitalSignature"),
    ],
)
def test_rejects_inappropriate_leaf_constraints(material, overrides, message) -> None:
    with pytest.raises(IssuedCertificateValidationError, match=message):
        _validate(material, _issued_certificate(material, **overrides))


@pytest.mark.parametrize(
    ("not_before", "not_after", "message"),
    [
        (NOW + timedelta(minutes=10), NOW + timedelta(days=30), "not yet valid"),
        (NOW - timedelta(days=31), NOW - timedelta(days=1), "expired"),
        (NOW - timedelta(minutes=1), NOW + timedelta(days=5), "lifetime"),
    ],
)
def test_rejects_invalid_validity(material, not_before, not_after, message) -> None:
    with pytest.raises(IssuedCertificateValidationError, match=message):
        _validate(
            material,
            _issued_certificate(material, not_before=not_before, not_after=not_after),
        )


def test_rejects_certificate_not_signed_by_configured_ca(material) -> None:
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Other CA")])
    other_ca = (
        x509.CertificateBuilder()
        .subject_name(other_name)
        .issuer_name(other_name)
        .public_key(other_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
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
            x509.SubjectKeyIdentifier.from_public_key(other_key.public_key()),
            critical=False,
        )
        .sign(other_key, hashes.SHA256())
    )

    with pytest.raises(IssuedCertificateValidationError, match="configured CA"):
        _validate(
            material,
            _issued_certificate(material),
            trusted_ca_data=_pem(other_ca),
        )


def test_rejects_non_ca_or_ambiguous_trust_data(material) -> None:
    leaf_pem = _pem(_issued_certificate(material))

    with pytest.raises(IssuedCertificateValidationError, match="non-CA"):
        _validate(
            material,
            _issued_certificate(material),
            trusted_ca_data=leaf_pem,
        )
    with pytest.raises(IssuedCertificateValidationError, match="malformed"):
        _validate(
            material,
            _issued_certificate(material),
            trusted_ca_data=_ca_pem(material) + b"unexpected text",
        )


@pytest.mark.parametrize(
    "certificate_data",
    [b"", b"not a certificate", b"-----BEGIN CERTIFICATE-----\ninvalid\n"],
)
def test_rejects_malformed_certificate(material, certificate_data) -> None:
    with pytest.raises(IssuedCertificateValidationError):
        validate_issued_certificate(
            certificate_data,
            material.csr_info,
            trusted_ca_data=_ca_pem(material),
            lifetime_days=30,
            now=NOW,
        )


def test_rejects_oversized_and_multiple_certificates(material) -> None:
    certificate_pem = _pem(_issued_certificate(material))

    with pytest.raises(IssuedCertificateValidationError, match="size limit"):
        validate_issued_certificate(
            b"x" * (MAX_ISSUED_CERTIFICATE_BYTES + 1),
            material.csr_info,
            trusted_ca_data=_ca_pem(material),
            lifetime_days=30,
            now=NOW,
        )
    with pytest.raises(IssuedCertificateValidationError, match="malformed"):
        validate_issued_certificate(
            certificate_pem + certificate_pem,
            material.csr_info,
            trusted_ca_data=_ca_pem(material),
            lifetime_days=30,
            now=NOW,
        )


def test_rejects_missing_csr_san_policy(material) -> None:
    csr_info = replace(material.csr_info, dns_sans=(), ip_sans=())

    with pytest.raises(IssuedCertificateValidationError, match="DNS SAN"):
        _validate(material, _issued_certificate(material), csr_info=csr_info)
