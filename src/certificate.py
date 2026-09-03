"""Read-only inspection and policy validation of public X.509 certificates."""

import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hmac import compare_digest
from ipaddress import ip_address

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID
from cryptography.x509.verification import PolicyBuilder, Store, VerificationError

from csr import CSRInfo
from public_key import (
    UnsupportedPublicKeyError,
    public_key_algorithm_and_size,
    spki_sha256,
)

MAX_CERTIFICATE_DER_BYTES = 1024 * 1024
MAX_ISSUED_CERTIFICATE_BYTES = 64 * 1024
MAX_TRUST_BUNDLE_BYTES = 256 * 1024
MIN_CERTIFICATE_LIFETIME_DAYS = 1
MAX_CERTIFICATE_LIFETIME_DAYS = 397
DEFAULT_CLOCK_SKEW = timedelta(minutes=5)

_CERTIFICATE_PEM_RE = re.compile(
    rb"[ \t\r\n]*-----BEGIN CERTIFICATE-----\r?\n"
    rb"(?:[A-Za-z0-9+/=]+\r?\n)+"
    rb"-----END CERTIFICATE-----[ \t\r\n]*\Z"
)
_CERTIFICATE_PEM_BLOCK_RE = re.compile(
    rb"[ \t\r\n]*-----BEGIN CERTIFICATE-----\r?\n"
    rb"(?:[A-Za-z0-9+/=]+\r?\n)+"
    rb"-----END CERTIFICATE-----"
)
_ALLOWED_SIGNATURE_HASHES = frozenset({"sha256", "sha384", "sha512"})
_SUPPORTED_RSA_KEY_SIZES = frozenset({2048, 3072, 4096})


class CertificateInspectionError(ValueError):
    """Raised when public certificate data cannot be inspected safely."""


class IssuedCertificateValidationError(CertificateInspectionError):
    """Raised when an issued certificate fails server-leaf policy."""


@dataclass(frozen=True, slots=True)
class CertificateInfo:
    """Validated, read-only metadata derived from an X.509 certificate."""

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
        return _certificate_info(certificate)
    except CertificateInspectionError:
        raise
    except UnsupportedAlgorithm as exc:
        raise CertificateInspectionError(
            "certificate uses an unsupported algorithm"
        ) from exc
    except (TypeError, ValueError, x509.DuplicateExtension) as exc:
        raise CertificateInspectionError("invalid certificate DER") from exc


def _certificate_info(certificate: x509.Certificate) -> CertificateInfo:
    try:
        public_key = certificate.public_key()
        public_key_algorithm, public_key_size = _public_key_info(public_key)
        dns_sans, ip_sans = _subject_alternative_names(certificate)
        subject_key_identifier = _subject_key_identifier(certificate)
        signature_hash = certificate.signature_hash_algorithm
        fingerprint = spki_sha256(public_key)
    except CertificateInspectionError:
        raise
    except (UnsupportedAlgorithm, UnsupportedPublicKeyError) as exc:
        raise CertificateInspectionError(
            "certificate uses an unsupported algorithm"
        ) from exc
    except (TypeError, ValueError, x509.DuplicateExtension) as exc:
        raise CertificateInspectionError("invalid certificate") from exc

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


def validate_issued_certificate(
    certificate_data: bytes,
    csr_info: CSRInfo,
    *,
    trusted_ca_data: bytes,
    lifetime_days: int,
    now: datetime | None = None,
    clock_skew: timedelta = DEFAULT_CLOCK_SKEW,
) -> CertificateInfo:
    """Validate one issued server leaf against its CSR and configured CA.

    Basic Constraints and serverAuth EKU are required. Key Usage is permitted
    to be absent under RFC 5280; when present, it must allow digital signatures
    and must not allow certificate or CRL signing. RSA key encipherment is
    optional.
    """

    if not isinstance(csr_info, CSRInfo):
        raise TypeError("CSR information must be CSRInfo")
    _validate_lifetime_days(lifetime_days)
    validation_time = _validation_time(now)
    if not isinstance(clock_skew, timedelta) or clock_skew < timedelta(0):
        raise ValueError("certificate clock skew must be a non-negative duration")

    certificate = _load_one_certificate(
        certificate_data,
        maximum=MAX_ISSUED_CERTIFICATE_BYTES,
        label="issued certificate",
    )
    info = _certificate_info(certificate)

    if (
        info.public_key_algorithm != "RSA"
        or info.public_key_size not in _SUPPORTED_RSA_KEY_SIZES
    ):
        raise IssuedCertificateValidationError(
            "issued certificate public key is unsupported for this signing policy"
        )
    if csr_info.unsupported_san_types:
        raise IssuedCertificateValidationError(
            "CSR contains an unsupported SAN identity type"
        )
    if not compare_digest(info.spki_sha256, csr_info.spki_sha256):
        raise IssuedCertificateValidationError(
            "issued certificate public key does not match the CSR"
        )
    if info.subject != csr_info.subject:
        raise IssuedCertificateValidationError(
            "issued certificate subject does not match the CSR"
        )
    _validate_exact_sans(certificate, csr_info)
    _validate_leaf_extensions(certificate)
    _validate_validity(certificate, lifetime_days, validation_time, clock_skew)
    _validate_signature_hash(certificate)
    _verify_ca_trust(certificate, trusted_ca_data, csr_info, validation_time)
    return info


def _load_one_certificate(
    certificate_data: bytes, *, maximum: int, label: str
) -> x509.Certificate:
    if not isinstance(certificate_data, bytes):
        raise TypeError(f"{label} data must be bytes")
    if not certificate_data:
        raise IssuedCertificateValidationError(f"{label} must not be empty")
    if len(certificate_data) > maximum:
        raise IssuedCertificateValidationError(f"{label} exceeds the size limit")
    try:
        if certificate_data.lstrip().startswith(b"-----BEGIN"):
            if _CERTIFICATE_PEM_RE.fullmatch(certificate_data) is None:
                raise IssuedCertificateValidationError(f"{label} is malformed")
            certificates = x509.load_pem_x509_certificates(certificate_data)
            if len(certificates) != 1:
                raise IssuedCertificateValidationError(
                    f"{label} must contain exactly one certificate"
                )
            return certificates[0]
        return x509.load_der_x509_certificate(certificate_data)
    except IssuedCertificateValidationError:
        raise
    except (TypeError, ValueError):
        raise IssuedCertificateValidationError(f"{label} is malformed") from None


def _load_trust_certificates(trusted_ca_data: bytes) -> list[x509.Certificate]:
    if not isinstance(trusted_ca_data, bytes):
        raise TypeError("trusted CA data must be bytes")
    if not trusted_ca_data:
        raise IssuedCertificateValidationError("trusted CA data must not be empty")
    if len(trusted_ca_data) > MAX_TRUST_BUNDLE_BYTES:
        raise IssuedCertificateValidationError("trusted CA data exceeds the size limit")
    try:
        if trusted_ca_data.lstrip().startswith(b"-----BEGIN"):
            position = 0
            while position < len(trusted_ca_data):
                match = _CERTIFICATE_PEM_BLOCK_RE.match(trusted_ca_data, position)
                if match is None:
                    if trusted_ca_data[position:].strip():
                        raise IssuedCertificateValidationError(
                            "trusted CA data is malformed"
                        )
                    break
                position = match.end()
            certificates = x509.load_pem_x509_certificates(trusted_ca_data)
        else:
            certificates = [x509.load_der_x509_certificate(trusted_ca_data)]
        for certificate in certificates:
            try:
                constraints = certificate.extensions.get_extension_for_class(
                    x509.BasicConstraints
                ).value
            except x509.ExtensionNotFound:
                raise IssuedCertificateValidationError(
                    "trusted CA certificate is missing Basic Constraints"
                ) from None
            if not constraints.ca:
                raise IssuedCertificateValidationError(
                    "trusted CA data contains a non-CA certificate"
                )
            try:
                key_usage = certificate.extensions.get_extension_for_class(
                    x509.KeyUsage
                ).value
            except x509.ExtensionNotFound:
                continue
            if not key_usage.key_cert_sign:
                raise IssuedCertificateValidationError(
                    "trusted CA certificate cannot sign certificates"
                )
    except IssuedCertificateValidationError:
        raise
    except (TypeError, ValueError):
        raise IssuedCertificateValidationError("trusted CA data is malformed") from None
    if not certificates:
        raise IssuedCertificateValidationError(
            "trusted CA data contains no certificates"
        )
    return certificates


def _require_extension(
    certificate: x509.Certificate,
    extension_class: type[x509.ExtensionType],
    label: str,
) -> x509.ExtensionType:
    try:
        return certificate.extensions.get_extension_for_class(extension_class).value
    except x509.ExtensionNotFound:
        raise IssuedCertificateValidationError(
            f"issued certificate is missing {label}"
        ) from None


def _validate_exact_sans(certificate: x509.Certificate, csr_info: CSRInfo) -> None:
    value = _require_extension(
        certificate, x509.SubjectAlternativeName, "Subject Alternative Name"
    )
    assert isinstance(value, x509.SubjectAlternativeName)
    if any(not isinstance(name, (x509.DNSName, x509.IPAddress)) for name in value):
        raise IssuedCertificateValidationError(
            "issued certificate SAN contains an unsupported identity type"
        )

    actual_dns = tuple(value.get_values_for_type(x509.DNSName))
    expected_dns = tuple(csr_info.dns_sans)
    if len(actual_dns) != len(expected_dns) or {
        name.casefold() for name in actual_dns
    } != {name.casefold() for name in expected_dns}:
        raise IssuedCertificateValidationError(
            "issued certificate DNS SANs do not exactly match the CSR"
        )

    actual_ips = tuple(value.get_values_for_type(x509.IPAddress))
    expected_ips = tuple(ip_address(address) for address in csr_info.ip_sans)
    if len(actual_ips) != len(expected_ips) or set(actual_ips) != set(expected_ips):
        raise IssuedCertificateValidationError(
            "issued certificate IP SANs do not exactly match the CSR"
        )


def _validate_leaf_extensions(certificate: x509.Certificate) -> None:
    basic_constraints = _require_extension(
        certificate, x509.BasicConstraints, "Basic Constraints"
    )
    assert isinstance(basic_constraints, x509.BasicConstraints)
    if basic_constraints.ca:
        raise IssuedCertificateValidationError(
            "issued certificate Basic Constraints must set CA to FALSE"
        )

    extended_key_usage = _require_extension(
        certificate, x509.ExtendedKeyUsage, "Extended Key Usage"
    )
    assert isinstance(extended_key_usage, x509.ExtendedKeyUsage)
    if set(extended_key_usage) != {ExtendedKeyUsageOID.SERVER_AUTH}:
        raise IssuedCertificateValidationError(
            "issued certificate Extended Key Usage must contain only serverAuth"
        )

    try:
        key_usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        return
    if key_usage.key_cert_sign or key_usage.crl_sign:
        raise IssuedCertificateValidationError(
            "issued certificate Key Usage permits CA signing"
        )
    if not key_usage.digital_signature:
        raise IssuedCertificateValidationError(
            "issued certificate Key Usage must permit digitalSignature"
        )


def _validate_lifetime_days(lifetime_days: int) -> None:
    if (
        not isinstance(lifetime_days, int)
        or isinstance(lifetime_days, bool)
        or not MIN_CERTIFICATE_LIFETIME_DAYS
        <= lifetime_days
        <= MAX_CERTIFICATE_LIFETIME_DAYS
    ):
        raise ValueError(
            "certificate lifetime must be between "
            f"{MIN_CERTIFICATE_LIFETIME_DAYS} and "
            f"{MAX_CERTIFICATE_LIFETIME_DAYS} days"
        )


def _validation_time(now: datetime | None) -> datetime:
    if now is None:
        return datetime.now(UTC)
    if not isinstance(now, datetime) or now.tzinfo is None:
        raise ValueError("certificate validation time must be timezone-aware")
    return now


def _validate_validity(
    certificate: x509.Certificate,
    lifetime_days: int,
    now: datetime,
    clock_skew: timedelta,
) -> None:
    not_before = _not_valid_before_utc(certificate)
    not_after = _not_valid_after_utc(certificate)
    if not_after <= not_before:
        raise IssuedCertificateValidationError(
            "issued certificate validity period is invalid"
        )
    if not_before > now + clock_skew:
        raise IssuedCertificateValidationError("issued certificate is not yet valid")
    if not_after <= now:
        raise IssuedCertificateValidationError("issued certificate has expired")

    actual_lifetime = not_after - not_before
    expected_lifetime = timedelta(days=lifetime_days)
    tolerance = timedelta(days=1)
    if (
        not expected_lifetime - tolerance
        <= actual_lifetime
        <= expected_lifetime + tolerance
    ):
        raise IssuedCertificateValidationError(
            "issued certificate validity period does not match the requested lifetime"
        )


def _validate_signature_hash(certificate: x509.Certificate) -> None:
    try:
        signature_hash = certificate.signature_hash_algorithm
    except UnsupportedAlgorithm:
        raise IssuedCertificateValidationError(
            "issued certificate signature hash algorithm is unsupported"
        ) from None
    if signature_hash is None or signature_hash.name not in _ALLOWED_SIGNATURE_HASHES:
        raise IssuedCertificateValidationError(
            "issued certificate signature hash is not allowed"
        )


def _verify_ca_trust(
    certificate: x509.Certificate,
    trusted_ca_data: bytes,
    csr_info: CSRInfo,
    now: datetime,
) -> None:
    trusted_certificates = _load_trust_certificates(trusted_ca_data)
    if csr_info.dns_sans:
        identity: x509.GeneralName = x509.DNSName(csr_info.dns_sans[0])
    elif csr_info.ip_sans:
        identity = x509.IPAddress(ip_address(csr_info.ip_sans[0]))
    else:
        raise IssuedCertificateValidationError(
            "CSR must contain at least one DNS or IP SAN"
        )

    try:
        verifier = (
            PolicyBuilder()
            .store(Store(trusted_certificates))
            .time(now)
            .build_server_verifier(identity)
        )
        verifier.verify(certificate, [])
    except (TypeError, ValueError, VerificationError):
        raise IssuedCertificateValidationError(
            "issued certificate failed verification against the configured CA"
        ) from None


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
