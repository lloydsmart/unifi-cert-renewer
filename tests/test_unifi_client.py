from datetime import UTC, datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from certificate import CertificateInspectionError
from unifi_client import (
    MAX_KEYTOOL_OUTPUT_CHARS,
    MAX_METADATA_VALUE_CHARS,
    ExpectedAliasNotFoundError,
    KeytoolMetadataError,
    UnexpectedEntryTypeError,
    inspect_unifi_certificate,
    parse_keytool_metadata,
)

KEYTOOL_OUTPUT = """\
Keystore type: PKCS12
Keystore provider: SUN

Your keystore contains 1 entry

Alias name: unifi
Creation date: Jul 23, 2024
Entry type: PrivateKeyEntry
Certificate chain length: 1
Certificate[1]:
Owner: CN=value-that-must-not-be-parsed
Issuer: CN=value-that-must-not-be-parsed
Serial number: deadbeef
"""


def test_parses_pkcs12_sun_and_unifi_alias_metadata() -> None:
    keystore, alias = parse_keytool_metadata(KEYTOOL_OUTPUT)

    assert keystore.keystore_type == "PKCS12"
    assert keystore.provider == "SUN"
    assert alias.alias_name == "unifi"
    assert alias.entry_type == "PrivateKeyEntry"
    assert alias.certificate_chain_length == 1


def test_combines_keytool_metadata_with_der_certificate_data() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "from-der")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(1)
        .not_valid_before(datetime(2026, 1, 1, tzinfo=UTC))
        .not_valid_after(datetime(2027, 1, 1, tzinfo=UTC))
        .sign(private_key, hashes.SHA256())
    )

    result = inspect_unifi_certificate(
        KEYTOOL_OUTPUT,
        certificate.public_bytes(serialization.Encoding.DER),
    )

    assert result.keystore.keystore_type == "PKCS12"
    assert result.alias.alias_name == "unifi"
    assert result.certificate.subject == "CN=from-der"


def test_rejects_missing_expected_alias() -> None:
    output = KEYTOOL_OUTPUT.replace("Alias name: unifi", "Alias name: other")

    with pytest.raises(ExpectedAliasNotFoundError, match="alias is missing"):
        parse_keytool_metadata(output)


def test_rejects_trusted_certificate_entry_before_requiring_chain_length() -> None:
    output = KEYTOOL_OUTPUT.replace(
        "Entry type: PrivateKeyEntry\nCertificate chain length: 1\n",
        "Entry type: trustedCertEntry\n",
    )

    with pytest.raises(UnexpectedEntryTypeError, match="PrivateKeyEntry"):
        parse_keytool_metadata(output)


@pytest.mark.parametrize(
    ("output", "message"),
    [
        (KEYTOOL_OUTPUT.replace("Keystore type: PKCS12\n", ""), "type.*missing"),
        (
            KEYTOOL_OUTPUT.replace("Keystore provider: SUN\n", ""),
            "provider.*missing",
        ),
        (
            KEYTOOL_OUTPUT.replace("Entry type: PrivateKeyEntry\n", ""),
            "entry type.*missing",
        ),
        (
            KEYTOOL_OUTPUT.replace("Certificate chain length: 1", ""),
            "chain length.*missing",
        ),
        (
            KEYTOOL_OUTPUT.replace(
                "Certificate chain length: 1", "Certificate chain length: many"
            ),
            "not a valid integer",
        ),
        (
            KEYTOOL_OUTPUT.replace(
                "Certificate chain length: 1", "Certificate chain length: 0"
            ),
            "must be positive",
        ),
    ],
)
def test_rejects_malformed_keytool_metadata(output: str, message: str) -> None:
    with pytest.raises(KeytoolMetadataError, match=message):
        parse_keytool_metadata(output)


def test_combined_inspection_rejects_invalid_certificate_der() -> None:
    with pytest.raises(CertificateInspectionError, match="invalid certificate DER"):
        inspect_unifi_certificate(KEYTOOL_OUTPUT, b"not DER")


def test_rejects_keytool_output_over_size_limit() -> None:
    oversized_output = "x" * (MAX_KEYTOOL_OUTPUT_CHARS + 1)

    with pytest.raises(KeytoolMetadataError, match="exceeds the size limit"):
        parse_keytool_metadata(oversized_output)


@pytest.mark.parametrize("label", ["Keystore type", "Keystore provider"])
def test_rejects_duplicated_keystore_metadata(label: str) -> None:
    existing_line = next(
        line for line in KEYTOOL_OUTPUT.splitlines() if line.startswith(f"{label}:")
    )
    output = KEYTOOL_OUTPUT.replace(existing_line, f"{existing_line}\n{existing_line}")

    with pytest.raises(KeytoolMetadataError, match="metadata is duplicated"):
        parse_keytool_metadata(output)


def test_rejects_duplicated_expected_alias_section() -> None:
    duplicate_alias = """\
Alias name: unifi
Entry type: PrivateKeyEntry
Certificate chain length: 1
"""

    with pytest.raises(KeytoolMetadataError, match="alias metadata is duplicated"):
        parse_keytool_metadata(f"{KEYTOOL_OUTPUT}\n{duplicate_alias}")


def test_rejects_control_characters_in_parsed_metadata() -> None:
    output = KEYTOOL_OUTPUT.replace(
        "Keystore provider: SUN", "Keystore provider: S\x1bUN"
    )

    with pytest.raises(KeytoolMetadataError, match="control characters"):
        parse_keytool_metadata(output)


def test_rejects_overlong_parsed_metadata() -> None:
    overlong_provider = "S" * (MAX_METADATA_VALUE_CHARS + 1)
    output = KEYTOOL_OUTPUT.replace(
        "Keystore provider: SUN", f"Keystore provider: {overlong_provider}"
    )

    with pytest.raises(KeytoolMetadataError, match="exceeds the size limit"):
        parse_keytool_metadata(output)
