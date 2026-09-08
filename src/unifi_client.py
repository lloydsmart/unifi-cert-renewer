"""Public inspection, command construction, and guarded UniFi execution seams."""

import re
import unicodedata
from collections.abc import Sequence
from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import datetime
from ipaddress import ip_address
from pathlib import PurePosixPath
from typing import Protocol

from cryptography import x509

from certificate import (
    MAX_CERTIFICATE_DER_BYTES,
    CertificateInfo,
    build_validated_certificate_reply,
    inspect_certificate,
)
from csr import CSRInfo, inspect_csr, validate_csr_spki

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
UNIFI_ALIAS = "unifi"
UNIFI_KEYSTORE_PATH = "/config/data/keystore"
UNIFI_PASSWORD_ENV_NAME = "UNIFI_KEYSTORE_PASSWORD"
MAX_PUBLIC_CHAIN_LENGTH = 10


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


class UnifiOperationError(ValueError):
    """A failed UniFi stage; messages never include raw execution diagnostics."""


@dataclass(frozen=True, slots=True)
class CertificatePolicy:
    """Operator-configured identity and continuity, independent of returned data."""

    expected_spki_sha256: str
    subject: str
    dns_sans: tuple[str, ...] = ()
    ip_sans: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class PublicKeystoreState:
    """Captured public data only; chain is ordered leaf first."""

    keytool_output: str
    certificate_chain_der: tuple[bytes, ...]


@dataclass(frozen=True, slots=True)
class CertificateImportRequest:
    """Public transaction inputs, revalidated every time installation is attempted.

    This is not an authorization token. Constructing/replacing this dataclass
    cannot skip validation or change the fixed command target.
    """

    before: PublicKeystoreState
    policy: CertificatePolicy
    csr_pem: bytes
    issued_certificate: bytes
    trusted_ca_data: bytes
    lifetime_days: int


@dataclass(frozen=True, slots=True)
class CertificateImportPlan:
    """Reviewable validation result; only public bytes go to the execution seam."""

    argv: tuple[str, ...]
    reply_pem: bytes
    certificate_chain_der: tuple[bytes, bytes]
    issued: CertificateInfo


class UnifiExecutionBoundary(Protocol):
    """Trusted, future UniFi-side adapter; no implementation is shipped.

    Operations target only the fixed UniFi entry. Adapters must enforce bounded
    IO/timeouts, safe local secret loading, direct argv execution, and serialize
    changes from the final inspection through import and post-inspection.
    The exclusive context must never suppress exceptions. The production adapter
    must exclude every writer (other renewers, UniFi, and host tools) throughout
    fresh inspection, import, and post-inspection. Keytool supplies no assumed
    single-writer guarantee; a Python lock alone is insufficient. This guarantee
    remains a production-executor requirement, not an implemented host lock.
    See docs/certificate-installation.md before implementing one.
    """

    def exclusive(self) -> AbstractContextManager[None]: ...

    def inspect_public_state(self) -> PublicKeystoreState: ...

    def generate_csr(self, argv: tuple[str, ...]) -> bytes: ...

    def import_certificate_reply(
        self, plan: CertificateImportPlan, *, expected_before: PublicKeystoreState
    ) -> int:
        """Feed reply_pem to stdin; return exit status only, never diagnostics."""
        ...


def build_keytool_importcert_command(
    *,
    alias: str = UNIFI_ALIAS,
    keystore_path: str = UNIFI_KEYSTORE_PATH,
    password_env_name: str = UNIFI_PASSWORD_ENV_NAME,
) -> tuple[str, ...]:
    """Build argv using the reported live Java 25 stdin/chain/noprompt semantics.

    The wrong-key rejection observed live does not establish crash-safe writes
    or writer exclusion. No arbitrary target or file IO is provided here.
    """

    if alias != UNIFI_ALIAS:
        raise UnifiOperationError("certificate import requires the unifi alias")
    if keystore_path != UNIFI_KEYSTORE_PATH:
        raise UnifiOperationError("certificate import requires the fixed UniFi path")
    if password_env_name != UNIFI_PASSWORD_ENV_NAME:
        raise UnifiOperationError("certificate import requires the fixed password name")
    return (
        "/usr/bin/keytool",
        "-importcert",
        "-alias",
        UNIFI_ALIAS,
        "-keystore",
        UNIFI_KEYSTORE_PATH,
        "-storetype",
        "PKCS12",
        "-storepass:env",
        UNIFI_PASSWORD_ENV_NAME,
        "-keypass:env",
        UNIFI_PASSWORD_ENV_NAME,
        "-noprompt",
    )


def inspect_public_keystore_state(
    state: PublicKeystoreState,
) -> UnifiCertificateInspection:
    """Derive metadata from bounded raw public data, not caller-supplied summaries."""

    if not isinstance(state, PublicKeystoreState):
        raise UnifiOperationError("invalid public keystore state")
    chain = state.certificate_chain_der
    if not isinstance(chain, tuple) or not 1 <= len(chain) <= MAX_PUBLIC_CHAIN_LENGTH:
        raise UnifiOperationError("invalid public certificate chain length")
    for der in chain:
        if not isinstance(der, bytes) or len(der) > MAX_CERTIFICATE_DER_BYTES:
            raise UnifiOperationError("invalid public certificate chain data")
        inspect_certificate(der)
    inspection = inspect_unifi_certificate(state.keytool_output, chain[0])
    if inspection.keystore != KeystoreMetadata("PKCS12", "SUN"):
        raise UnifiOperationError("unsupported UniFi keystore type or provider")
    if inspection.alias.certificate_chain_length != len(chain):
        raise UnifiOperationError("public chain does not match keytool chain length")
    return inspection


def build_unifi_csr_command(policy: CertificatePolicy) -> tuple[str, ...]:
    """Validate configured identity before any operation and fix the deployment target."""

    if not isinstance(policy, CertificatePolicy):
        raise UnifiOperationError("invalid certificate policy")
    if (
        not isinstance(policy.expected_spki_sha256, str)
        or re.fullmatch(r"[0-9a-fA-F]{64}", policy.expected_spki_sha256) is None
    ):
        raise UnifiOperationError("invalid expected SPKI SHA-256")
    if not isinstance(policy.dns_sans, tuple) or not isinstance(policy.ip_sans, tuple):
        raise UnifiOperationError("certificate policy SANs must be immutable tuples")
    argv = build_keytool_certreq_command(
        alias=UNIFI_ALIAS,
        keystore_path=UNIFI_KEYSTORE_PATH,
        password_env_name=UNIFI_PASSWORD_ENV_NAME,
        subject=policy.subject,
        dns_sans=policy.dns_sans,
        ip_sans=policy.ip_sans,
    )
    try:
        x509.Name.from_rfc4514_string(policy.subject)
    except ValueError:
        raise UnifiOperationError("invalid configured subject DN") from None
    return ("/usr/bin/keytool", *argv[1:], "-sigalg", "SHA384withRSA")


def validate_requested_csr(csr_pem: bytes, policy: CertificatePolicy) -> CSRInfo:
    """Reparse proof-of-possession and require the operator's exact identity policy."""

    build_unifi_csr_command(policy)
    info = inspect_csr(csr_pem)
    validate_csr_spki(info, policy.expected_spki_sha256)
    expected_subject = x509.Name.from_rfc4514_string(policy.subject).rfc4514_string()
    if info.subject != expected_subject:
        raise UnifiOperationError("CSR subject differs from configured policy")
    if (
        info.unsupported_san_types
        or len(info.dns_sans) != len(policy.dns_sans)
        or {name.lower() for name in info.dns_sans}
        != {name.lower() for name in policy.dns_sans}
        or len(info.ip_sans) != len(policy.ip_sans)
        or set(info.ip_sans) != {str(ip_address(address)) for address in policy.ip_sans}
    ):
        raise UnifiOperationError("CSR SANs differ from configured policy")
    if info.public_key_algorithm != "RSA" or info.public_key_size not in {
        2048,
        3072,
        4096,
    }:
        raise UnifiOperationError("CSR key is unsupported for signing")
    if info.signature_hash_algorithm not in {"sha256", "sha384", "sha512"}:
        raise UnifiOperationError("CSR signature hash is unsupported for signing")
    return info


def prepare_certificate_import(
    request: CertificateImportRequest, *, now: datetime | None = None
) -> CertificateImportPlan:
    """The sole import preparation path: raw CSR, leaf, CA, and preconditions checked."""

    if not isinstance(request, CertificateImportRequest):
        raise UnifiOperationError("invalid certificate import request")
    before = inspect_public_keystore_state(request.before)
    csr_info = validate_requested_csr(request.csr_pem, request.policy)
    validate_csr_spki(csr_info, before.certificate.spki_sha256)
    issued, chain, reply = build_validated_certificate_reply(
        request.issued_certificate,
        csr_info,
        trusted_ca_data=request.trusted_ca_data,
        lifetime_days=request.lifetime_days,
        now=now,
    )
    return CertificateImportPlan(
        build_keytool_importcert_command(), reply, chain, issued
    )


def verify_certificate_import(
    after: PublicKeystoreState,
    request: CertificateImportRequest,
    *,
    now: datetime | None = None,
) -> UnifiCertificateInspection:
    """Prove the unchanged entry/key and exact issued leaf and CA after import."""

    plan = prepare_certificate_import(request, now=now)
    inspection = inspect_public_keystore_state(after)
    if inspection.certificate.spki_sha256 != plan.issued.spki_sha256:
        raise UnifiOperationError("post-import public key changed")
    if inspection.certificate.certificate_sha256 != plan.issued.certificate_sha256:
        raise UnifiOperationError(
            "post-import certificate fingerprint differs from issued"
        )
    if inspection.certificate != plan.issued:
        raise UnifiOperationError(
            "post-import certificate metadata differs from issued"
        )
    if after.certificate_chain_der != plan.certificate_chain_der:
        raise UnifiOperationError(
            "post-import public certificate chain differs from issued"
        )
    return inspection


class UnifiClient:
    """Compose only constrained adapter operations; never opens a keystore itself."""

    def __init__(self, boundary: UnifiExecutionBoundary):
        self._boundary = boundary

    def inspect_current(self, policy: CertificatePolicy) -> PublicKeystoreState:
        try:
            build_unifi_csr_command(policy)
            state = self._boundary.inspect_public_state()
            inspection = inspect_public_keystore_state(state)
            if (
                inspection.certificate.spki_sha256
                != policy.expected_spki_sha256.lower()
            ):
                raise UnifiOperationError("current public key differs from expected")
            return state
        except Exception:
            raise UnifiOperationError("UniFi public inspection failed") from None

    def request_csr(self, policy: CertificatePolicy) -> bytes:
        try:
            argv = build_unifi_csr_command(policy)
            csr_pem = self._boundary.generate_csr(argv)
            validate_requested_csr(csr_pem, policy)
            return csr_pem
        except Exception:
            raise UnifiOperationError(
                "UniFi CSR generation or validation failed"
            ) from None

    def install_certificate(
        self, request: CertificateImportRequest
    ) -> UnifiCertificateInspection:
        """Revalidate just before mutation; return keystore evidence, never renewal success.

        No caller-controlled time override exists on this execution path.
        Failure after dispatch has an uncertain mutation outcome; never retry
        automatically, restart, or attempt an implicit rollback.
        Recovery requires fresh public inspection even if keytool reported a
        wrong-key error. Cancellation propagates without a result; process death
        and any surviving child must be handled by the future executor before
        it permits recovery inspection or another writer.
        """

        stage = "pre-import validation"
        try:
            with self._boundary.exclusive():
                plan = prepare_certificate_import(request)
                current = self._boundary.inspect_public_state()
                old_info = inspect_public_keystore_state(request.before)
                current_info = inspect_public_keystore_state(current)
                if (
                    current_info != old_info
                    or current.certificate_chain_der
                    != request.before.certificate_chain_der
                ):
                    raise UnifiOperationError(
                        "public keystore state changed before import"
                    )
                stage = "certificate import; keystore may have changed"
                status = self._boundary.import_certificate_reply(
                    plan, expected_before=current
                )
                if type(status) is not int or status != 0:
                    raise UnifiOperationError("keytool certificate import failed")
                stage = "post-import verification; keystore may have changed"
                after = self._boundary.inspect_public_state()
                result = verify_certificate_import(after, request)
            return result
        except Exception:
            raise UnifiOperationError(f"UniFi {stage} failed") from None


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
