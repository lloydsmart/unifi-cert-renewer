"""Read-only inspection of public X.509 certificates."""

from dataclasses import dataclass
from datetime import UTC, datetime

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID

from public_key import (
    UnsupportedPublicKeyError,
    public_key_algorithm_and_size,
    spki_sha256,
)

MAX_CERTIFICATE_DER_BYTES = 1024 * 1024


class CertificateInspectionError(ValueError):
    """Raised when public certificate data cannot be inspected safely."""


@dataclass(frozen=True, slots=True)
class CertificateInfo:
    """Validated, read-only metadata derived from a DER X.509 certificate."""

    subject: str
    issuer: str
    serial_number: str
    not_valid_before: datetime
    not_valid_after: datetime
    certificate_sha256: str
    spki_sha256: str
    public_key_algorithm: str
    public_key_size: int | None
    dns_sans: tuple[str, ...]
    ip_sans: tuple[str, ...]
    subject_key_identifier: str | None
    signature_algorithm_oid: str
    signature_hash_algorithm: str | None


def inspect_certificate(certificate_der: bytes) -> CertificateInfo:
    """Return inspection metadata derived exclusively from public DER data."""

    if not isinstance(certificate_der, bytes):
        raise TypeError("certificate DER must be bytes")
    if not certificate_der:
        raise CertificateInspectionError("certificate DER must not be empty")
    if len(certificate_der) > MAX_CERTIFICATE_DER_BYTES:
        raise CertificateInspectionError("certificate DER exceeds the size limit")

    try:
        certificate = x509.load_der_x509_certificate(certificate_der)
        public_key = certificate.public_key()
        public_key_algorithm, public_key_size = _public_key_info(public_key)
        dns_sans, ip_sans = _subject_alternative_names(certificate)
        subject_key_identifier = _subject_key_identifier(certificate)
        signature_hash = certificate.signature_hash_algorithm
        fingerprint = spki_sha256(public_key)
    except CertificateInspectionError:
        raise
    except UnsupportedPublicKeyError as exc:
        raise CertificateInspectionError(
            "unsupported certificate public-key algorithm"
        ) from exc
    except UnsupportedAlgorithm as exc:
        raise CertificateInspectionError(
            "certificate uses an unsupported algorithm"
        ) from exc
    except (TypeError, ValueError, x509.DuplicateExtension) as exc:
        raise CertificateInspectionError("invalid certificate DER") from exc

    return CertificateInfo(
        subject=certificate.subject.rfc4514_string(),
        issuer=certificate.issuer.rfc4514_string(),
        serial_number=format(certificate.serial_number, "x"),
        not_valid_before=_not_valid_before_utc(certificate),
        not_valid_after=_not_valid_after_utc(certificate),
        certificate_sha256=certificate.fingerprint(hashes.SHA256()).hex(),
        spki_sha256=fingerprint,
        public_key_algorithm=public_key_algorithm,
        public_key_size=public_key_size,
        dns_sans=dns_sans,
        ip_sans=ip_sans,
        subject_key_identifier=subject_key_identifier,
        signature_algorithm_oid=certificate.signature_algorithm_oid.dotted_string,
        signature_hash_algorithm=(signature_hash.name if signature_hash else None),
    )


def _public_key_info(public_key: object) -> tuple[str, int | None]:
    try:
        return public_key_algorithm_and_size(public_key)
    except UnsupportedPublicKeyError as exc:
        raise CertificateInspectionError(
            "unsupported certificate public-key algorithm"
        ) from exc


def _subject_alternative_names(
    certificate: x509.Certificate,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    try:
        extension = certificate.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
    except x509.ExtensionNotFound:
        return (), ()

    alternative_names = extension.value
    dns_sans = tuple(alternative_names.get_values_for_type(x509.DNSName))
    ip_sans = tuple(
        str(address)
        for address in alternative_names.get_values_for_type(x509.IPAddress)
    )
    return dns_sans, ip_sans


def _subject_key_identifier(certificate: x509.Certificate) -> str | None:
    try:
        extension = certificate.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_KEY_IDENTIFIER
        )
    except x509.ExtensionNotFound:
        return None
    return extension.value.digest.hex()


def _not_valid_before_utc(certificate: x509.Certificate) -> datetime:
    value = getattr(certificate, "not_valid_before_utc", None)
    if value is not None:
        return value
    return certificate.not_valid_before.replace(tzinfo=UTC)


def _not_valid_after_utc(certificate: x509.Certificate) -> datetime:
    value = getattr(certificate, "not_valid_after_utc", None)
    if value is not None:
        return value
    return certificate.not_valid_after.replace(tzinfo=UTC)
