"""Bounded inspection and key-continuity validation for public PKCS#10 CSRs."""

import re
from dataclasses import dataclass
from hmac import compare_digest

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.x509.oid import ExtensionOID

from public_key import (
    UnsupportedPublicKeyError,
    public_key_algorithm_and_size,
    spki_sha256,
)

MAX_CSR_PEM_BYTES = 64 * 1024
_SHA256_HEX_RE = re.compile(r"[0-9A-Fa-f]{64}\Z")
_PEM_LABELS = (b"CERTIFICATE REQUEST", b"NEW CERTIFICATE REQUEST")


class CSRInspectionError(ValueError):
    """Base error for CSR inspection and validation failures."""


class MalformedCSRError(CSRInspectionError):
    """Raised when a CSR is malformed or uses an unsupported algorithm."""


class CSRValidationError(CSRInspectionError):
    """Base error for a well-formed CSR that fails an explicit validation."""


class InvalidCSRSignatureError(CSRValidationError):
    """Raised when a CSR's proof-of-possession signature is invalid."""


class InvalidSPKIFingerprintError(CSRValidationError):
    """Raised when an expected SPKI SHA-256 fingerprint is malformed."""


class ExpectedSPKIMismatchError(CSRValidationError):
    """Raised when a CSR does not contain the expected public key."""


@dataclass(frozen=True, slots=True)
class CSRInfo:
    """Validated, read-only metadata derived from a public PKCS#10 CSR."""

    subject: str
    spki_sha256: str
    public_key_algorithm: str
    public_key_size: int | None
    dns_sans: tuple[str, ...]
    ip_sans: tuple[str, ...]
    subject_key_identifier: str | None
    signature_algorithm_oid: str
    signature_hash_algorithm: str | None
    signature_valid: bool


def inspect_csr(csr_pem: bytes) -> CSRInfo:
    """Parse and cryptographically validate one public PEM PKCS#10 CSR."""

    if not isinstance(csr_pem, bytes):
        raise TypeError("CSR PEM must be bytes")
    if not csr_pem:
        raise MalformedCSRError("CSR PEM must not be empty")
    if len(csr_pem) > MAX_CSR_PEM_BYTES:
        raise MalformedCSRError("CSR PEM exceeds the size limit")
    _require_single_pem_envelope(csr_pem)

    try:
        request = x509.load_pem_x509_csr(csr_pem)
        signature_valid = request.is_signature_valid
        if not signature_valid:
            raise InvalidCSRSignatureError(
                "CSR proof-of-possession signature is invalid"
            )
        public_key = request.public_key()
        public_key_algorithm, public_key_size = public_key_algorithm_and_size(
            public_key
        )
        dns_sans, ip_sans = _subject_alternative_names(request)
        subject_key_identifier = _subject_key_identifier(request)
        signature_hash = request.signature_hash_algorithm
        signature_algorithm_oid = request.signature_algorithm_oid.dotted_string
        fingerprint = spki_sha256(public_key)
        subject = request.subject.rfc4514_string()
    except CSRInspectionError:
        raise
    except UnsupportedAlgorithm as exc:
        raise MalformedCSRError("CSR uses an unsupported algorithm") from exc
    except UnsupportedPublicKeyError as exc:
        raise MalformedCSRError("CSR uses an unsupported public-key algorithm") from exc
    except (TypeError, ValueError, x509.DuplicateExtension) as exc:
        raise MalformedCSRError("invalid CSR PEM") from exc

    return CSRInfo(
        subject=subject,
        spki_sha256=fingerprint,
        public_key_algorithm=public_key_algorithm,
        public_key_size=public_key_size,
        dns_sans=dns_sans,
        ip_sans=ip_sans,
        subject_key_identifier=subject_key_identifier,
        signature_algorithm_oid=signature_algorithm_oid,
        signature_hash_algorithm=(signature_hash.name if signature_hash else None),
        signature_valid=True,
    )


def _require_single_pem_envelope(csr_pem: bytes) -> None:
    stripped = csr_pem.strip()
    for label in _PEM_LABELS:
        header = b"-----BEGIN " + label + b"-----"
        footer = b"-----END " + label + b"-----"
        if stripped.startswith(header):
            body = stripped[len(header) : -len(footer)]
            if not stripped.endswith(footer) or b"-----BEGIN " in body:
                raise MalformedCSRError("invalid CSR PEM")
            return
    raise MalformedCSRError("invalid CSR PEM")


def validate_csr_spki(csr_info: CSRInfo, expected_spki_sha256: str) -> None:
    """Require a parsed CSR to contain the expected DER SPKI SHA-256 value.

    Expected fingerprints may use either hex case and are canonicalized to
    lowercase before comparison. Whitespace and separators are not accepted.
    """

    if not isinstance(csr_info, CSRInfo):
        raise TypeError("CSR information must be CSRInfo")
    if not isinstance(expected_spki_sha256, str):
        raise TypeError("expected SPKI SHA-256 must be text")
    if _SHA256_HEX_RE.fullmatch(expected_spki_sha256) is None:
        raise InvalidSPKIFingerprintError(
            "expected SPKI SHA-256 must be exactly 64 hexadecimal characters"
        )

    expected = expected_spki_sha256.lower()
    if not compare_digest(csr_info.spki_sha256, expected):
        raise ExpectedSPKIMismatchError(
            "CSR public key does not match the expected SPKI SHA-256"
        )


def _subject_alternative_names(
    request: x509.CertificateSigningRequest,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    try:
        extension = request.extensions.get_extension_for_oid(
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


def _subject_key_identifier(
    request: x509.CertificateSigningRequest,
) -> str | None:
    try:
        extension = request.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_KEY_IDENTIFIER
        )
    except x509.ExtensionNotFound:
        return None
    return extension.value.digest.hex()
