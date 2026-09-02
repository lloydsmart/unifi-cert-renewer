"""Read-only parsing and command construction at the UniFi boundary."""

import re
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass
from ipaddress import ip_address
from pathlib import PurePosixPath

from certificate import CertificateInfo, inspect_certificate

MAX_KEYTOOL_OUTPUT_CHARS = 1024 * 1024
MAX_METADATA_VALUE_CHARS = 256
EXPECTED_ENTRY_TYPE = "PrivateKeyEntry"
MAX_ALIAS_CHARS = 256
MAX_KEYSTORE_PATH_CHARS = 4096
MAX_SUBJECT_DN_CHARS = 4096
MAX_DNS_SAN_CHARS = 253
MAX_IP_SAN_CHARS = 64
MAX_SAN_ENTRIES = 100
MAX_PASSWORD_ENV_NAME_CHARS = 128

_ENVIRONMENT_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_DNS_LABEL_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")
_UNSAFE_TEXT_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Zl", "Zp"})


class KeytoolMetadataError(ValueError):
    """Raised when required keytool metadata is absent or malformed."""


class ExpectedAliasNotFoundError(KeytoolMetadataError):
    """Raised when keytool output does not describe the requested alias."""


class UnexpectedEntryTypeError(KeytoolMetadataError):
    """Raised when an alias is not backed by a private-key entry."""


class CertreqCommandError(ValueError):
    """Raised when keytool certreq command inputs are unsafe or invalid."""


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


def build_keytool_certreq_command(
    *,
    alias: str,
    keystore_path: str,
    password_env_name: str,
    subject: str,
    dns_sans: Sequence[str] = (),
    ip_sans: Sequence[str] = (),
) -> tuple[str, ...]:
    """Build immutable argv for a future, direct ``keytool -certreq`` call.

    SANs are emitted deterministically: DNS entries in caller order, followed by
    IP entries in caller order with IP text canonicalized by ``ipaddress``.
    Semantically duplicate entries are rejected. The password
    environment-variable name is included, never its value.
    """

    _validate_bounded_text(alias, "alias", MAX_ALIAS_CHARS)
    _validate_keystore_path(keystore_path)
    _validate_bounded_text(subject, "subject DN", MAX_SUBJECT_DN_CHARS)
    _validate_password_env_name(password_env_name)

    validated_dns_sans = _validate_dns_sans(dns_sans)
    validated_ip_sans = _validate_ip_sans(ip_sans)
    if len(validated_dns_sans) + len(validated_ip_sans) > MAX_SAN_ENTRIES:
        raise CertreqCommandError("SAN count exceeds the size limit")
    if not validated_dns_sans and not validated_ip_sans:
        raise CertreqCommandError("at least one DNS or IP SAN is required")

    san_parts = [f"DNS:{name}" for name in validated_dns_sans]
    san_parts.extend(f"IP:{address}" for address in validated_ip_sans)
    san_extension = f"SAN={','.join(san_parts)}"

    return (
        "keytool",
        "-certreq",
        "-alias",
        alias,
        "-keystore",
        keystore_path,
        "-storepass:env",
        password_env_name,
        "-keypass:env",
        password_env_name,
        "-dname",
        subject,
        "-ext",
        san_extension,
        "-rfc",
    )


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


def _validate_bounded_text(value: str, label: str, maximum: int) -> None:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be text")
    if not value:
        raise CertreqCommandError(f"{label} must not be empty")
    if len(value) > maximum:
        raise CertreqCommandError(f"{label} exceeds the size limit")
    if any(
        unicodedata.category(character) in _UNSAFE_TEXT_CATEGORIES
        for character in value
    ):
        raise CertreqCommandError(f"{label} contains control characters")


def _validate_keystore_path(keystore_path: str) -> None:
    _validate_bounded_text(
        keystore_path,
        "keystore path",
        MAX_KEYSTORE_PATH_CHARS,
    )
    path = PurePosixPath(keystore_path)
    if not path.is_absolute():
        raise CertreqCommandError("keystore path must be an absolute POSIX path")
    if ".." in path.parts:
        raise CertreqCommandError("keystore path must not contain parent traversal")


def _validate_password_env_name(password_env_name: str) -> None:
    if not isinstance(password_env_name, str):
        raise TypeError("password environment-variable name must be text")
    if len(password_env_name) > MAX_PASSWORD_ENV_NAME_CHARS:
        raise CertreqCommandError(
            "password environment-variable name exceeds the size limit"
        )
    if _ENVIRONMENT_NAME_RE.fullmatch(password_env_name) is None:
        raise CertreqCommandError(
            "password environment-variable name must be a POSIX identifier"
        )


def _validate_dns_sans(dns_sans: Sequence[str]) -> tuple[str, ...]:
    values = _validate_san_sequence(dns_sans, "DNS SAN")
    validated: list[str] = []
    seen: set[str] = set()
    for value in values:
        _validate_bounded_text(value, "DNS SAN", MAX_DNS_SAN_CHARS)
        try:
            value.encode("ascii")
        except UnicodeEncodeError as exc:
            raise CertreqCommandError("DNS SAN must be an ASCII DNS name") from exc
        labels = value.split(".")
        if any(_DNS_LABEL_RE.fullmatch(label) is None for label in labels):
            raise CertreqCommandError("DNS SAN is not a valid DNS name")
        canonical = value.lower()
        if canonical in seen:
            raise CertreqCommandError("duplicate DNS SAN is not allowed")
        seen.add(canonical)
        validated.append(value)
    return tuple(validated)


def _validate_ip_sans(ip_sans: Sequence[str]) -> tuple[str, ...]:
    values = _validate_san_sequence(ip_sans, "IP SAN")
    validated: list[str] = []
    seen: set[str] = set()
    for value in values:
        _validate_bounded_text(value, "IP SAN", MAX_IP_SAN_CHARS)
        if "%" in value:
            raise CertreqCommandError("IP SAN must not contain a scope identifier")
        try:
            canonical = str(ip_address(value))
        except ValueError as exc:
            raise CertreqCommandError("IP SAN is not a valid IP address") from exc
        if canonical in seen:
            raise CertreqCommandError("duplicate IP SAN is not allowed")
        seen.add(canonical)
        validated.append(canonical)
    return tuple(validated)


def _validate_san_sequence(values: Sequence[str], label: str) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        raise TypeError(f"{label} values must be a sequence of text values")
    if len(values) > MAX_SAN_ENTRIES:
        raise CertreqCommandError(f"{label} count exceeds the size limit")
    return tuple(values)
