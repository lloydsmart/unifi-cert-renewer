"""Read-only parsing at the UniFi integration boundary."""

from dataclasses import dataclass

from certificate import CertificateInfo, inspect_certificate

MAX_KEYTOOL_OUTPUT_CHARS = 1024 * 1024
MAX_METADATA_VALUE_CHARS = 256
EXPECTED_ENTRY_TYPE = "PrivateKeyEntry"


class KeytoolMetadataError(ValueError):
    """Raised when required keytool metadata is absent or malformed."""


class ExpectedAliasNotFoundError(KeytoolMetadataError):
    """Raised when keytool output does not describe the requested alias."""


class UnexpectedEntryTypeError(KeytoolMetadataError):
    """Raised when an alias is not backed by a private-key entry."""


@dataclass(frozen=True, slots=True)
class KeystoreMetadata:
    """Non-secret metadata about the inspected Java keystore."""

    keystore_type: str
    provider: str


@dataclass(frozen=True, slots=True)
class AliasMetadata:
    """Non-secret keytool metadata for one keystore alias."""

    alias_name: str
    entry_type: str
    certificate_chain_length: int


@dataclass(frozen=True, slots=True)
class UnifiCertificateInspection:
    """Combined keytool and DER certificate inspection result."""

    keystore: KeystoreMetadata
    alias: AliasMetadata
    certificate: CertificateInfo


def parse_keytool_metadata(
    keytool_output: str,
    *,
    expected_alias: str = "unifi",
) -> tuple[KeystoreMetadata, AliasMetadata]:
    """Parse only required keystore and alias metadata from keytool text."""

    if not isinstance(keytool_output, str):
        raise TypeError("keytool output must be text")
    if not keytool_output:
        raise KeytoolMetadataError("keytool output must not be empty")
    if len(keytool_output) > MAX_KEYTOOL_OUTPUT_CHARS:
        raise KeytoolMetadataError("keytool output exceeds the size limit")
    _validate_metadata_value(expected_alias, "expected alias")

    global_values: dict[str, list[str]] = {
        "Keystore type": [],
        "Keystore provider": [],
    }
    alias_sections: list[dict[str, list[str]]] = []
    current_alias: dict[str, list[str]] | None = None

    for line in keytool_output.splitlines():
        label, separator, raw_value = line.partition(":")
        if not separator:
            continue
        label = label.strip()
        if label in global_values:
            global_values[label].append(raw_value.strip())
            continue
        if label == "Alias name":
            current_alias = {"Alias name": [raw_value.strip()]}
            alias_sections.append(current_alias)
            continue
        if current_alias is not None and label in {
            "Entry type",
            "Certificate chain length",
        }:
            current_alias.setdefault(label, []).append(raw_value.strip())

    keystore_type = _require_single_value(global_values, "Keystore type")
    provider = _require_single_value(global_values, "Keystore provider")

    matching_sections = [
        section
        for section in alias_sections
        if _optional_single_value(section, "Alias name") == expected_alias
    ]
    if not matching_sections:
        raise ExpectedAliasNotFoundError("expected alias is missing")
    if len(matching_sections) != 1:
        raise KeytoolMetadataError("expected alias metadata is duplicated")

    alias_section = matching_sections[0]
    alias_name = _require_single_value(alias_section, "Alias name")
    entry_type = _require_single_value(alias_section, "Entry type")
    if entry_type != EXPECTED_ENTRY_TYPE:
        raise UnexpectedEntryTypeError(
            "expected alias does not contain a PrivateKeyEntry"
        )

    chain_length_text = _require_single_value(alias_section, "Certificate chain length")
    if not chain_length_text.isascii() or not chain_length_text.isdecimal():
        raise KeytoolMetadataError("certificate chain length is not a valid integer")
    chain_length = int(chain_length_text)
    if chain_length < 1:
        raise KeytoolMetadataError("certificate chain length must be positive")

    return (
        KeystoreMetadata(keystore_type=keystore_type, provider=provider),
        AliasMetadata(
            alias_name=alias_name,
            entry_type=entry_type,
            certificate_chain_length=chain_length,
        ),
    )


def inspect_unifi_certificate(
    keytool_output: str,
    certificate_der: bytes,
    *,
    expected_alias: str = "unifi",
) -> UnifiCertificateInspection:
    """Combine captured keytool metadata with public certificate inspection."""

    keystore, alias = parse_keytool_metadata(
        keytool_output,
        expected_alias=expected_alias,
    )
    certificate = inspect_certificate(certificate_der)
    return UnifiCertificateInspection(
        keystore=keystore,
        alias=alias,
        certificate=certificate,
    )


def _optional_single_value(values: dict[str, list[str]], label: str) -> str | None:
    occurrences = values.get(label, [])
    if not occurrences:
        return None
    if len(occurrences) != 1:
        raise KeytoolMetadataError(f"{label.lower()} metadata is duplicated")
    value = occurrences[0]
    _validate_metadata_value(value, label.lower())
    return value


def _require_single_value(values: dict[str, list[str]], label: str) -> str:
    value = _optional_single_value(values, label)
    if value is None:
        raise KeytoolMetadataError(f"{label.lower()} metadata is missing")
    return value


def _validate_metadata_value(value: str, label: str) -> None:
    if not value:
        raise KeytoolMetadataError(f"{label} must not be empty")
    if len(value) > MAX_METADATA_VALUE_CHARS:
        raise KeytoolMetadataError(f"{label} exceeds the size limit")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise KeytoolMetadataError(f"{label} contains control characters")
