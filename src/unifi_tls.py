"""Fresh, strictly authenticated TLS verification for the UniFi endpoint."""

import hashlib
import math
import re
import socket
import ssl
import time
from dataclasses import dataclass
from ipaddress import ip_address

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from certificate import CertificateInspectionError, validate_installation_ca
from tls_policy import TLSConfigurationError, create_client_tls_context

MAX_HOST_CHARS = 253
MAX_LEAF_DER_BYTES = 64 * 1024
MAX_ATTEMPTS = 1000
_DNS_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")


class LiveTLSVerificationError(ValueError):
    """Safe-to-display failure of live endpoint verification."""


class EndpointNotReadyError(LiveTLSVerificationError):
    """The endpoint did not become reachable within the bounded policy."""


class TLSAuthenticationError(LiveTLSVerificationError):
    """The peer failed normal certificate-chain or hostname authentication."""


class TLSHandshakeError(LiveTLSVerificationError):
    """A reachable endpoint did not complete a TLS handshake."""


class ServedCertificateMismatchError(LiveTLSVerificationError):
    """The authenticated endpoint served a different leaf certificate."""


@dataclass(frozen=True, slots=True)
class LiveTLSEndpoint:
    """Network address and independently explicit TLS identity."""

    address: str
    server_hostname: str
    port: int = 8443


@dataclass(frozen=True, slots=True)
class ReadinessPolicy:
    """A deadline and attempt bound for post-resume endpoint readiness."""

    timeout_seconds: float = 60.0
    attempt_timeout_seconds: float = 5.0
    retry_delay_seconds: float = 0.5
    max_attempts: int = 120


DEFAULT_READINESS_POLICY = ReadinessPolicy()


@dataclass(frozen=True, slots=True)
class _PreparedLiveTLSVerification:
    endpoint: LiveTLSEndpoint
    readiness: ReadinessPolicy
    context: ssl.SSLContext


def validate_live_tls_configuration(
    endpoint: LiveTLSEndpoint, readiness: ReadinessPolicy
) -> None:
    if not isinstance(endpoint, LiveTLSEndpoint):
        raise LiveTLSVerificationError("invalid UniFi TLS endpoint")
    _validate_ip_address(endpoint.address)
    _validate_host(endpoint.server_hostname, "server identity")
    if type(endpoint.port) is not int or not 1 <= endpoint.port <= 65535:
        raise LiveTLSVerificationError("invalid UniFi TLS port")
    if not isinstance(readiness, ReadinessPolicy):
        raise LiveTLSVerificationError("invalid UniFi readiness policy")
    for value, label, allow_zero in (
        (readiness.timeout_seconds, "timeout", False),
        (readiness.attempt_timeout_seconds, "attempt timeout", False),
        (readiness.retry_delay_seconds, "retry delay", True),
    ):
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or value < 0
            or (not allow_zero and value == 0)
        ):
            raise LiveTLSVerificationError(f"invalid UniFi readiness {label}")
    if (
        type(readiness.max_attempts) is not int
        or not 1 <= readiness.max_attempts <= MAX_ATTEMPTS
    ):
        raise LiveTLSVerificationError("invalid UniFi readiness attempt limit")


def verify_live_tls_certificate(
    *,
    endpoint: LiveTLSEndpoint,
    readiness: ReadinessPolicy,
    trusted_ca_data: bytes,
    expected_leaf_der: bytes,
) -> str:
    """Return the exact served leaf SHA-256 after a fresh verified connection.

    Only pre-authentication connection failures are retried. Once TLS
    authentication succeeds, an exact-leaf mismatch is an immediate hard failure.
    """

    prepared = prepare_live_tls_verification(
        endpoint=endpoint,
        readiness=readiness,
        trusted_ca_data=trusted_ca_data,
    )
    return verify_prepared_live_tls_certificate(
        prepared=prepared, expected_leaf_der=expected_leaf_der
    )


def prepare_live_tls_verification(
    *,
    endpoint: LiveTLSEndpoint,
    readiness: ReadinessPolicy,
    trusted_ca_data: bytes,
) -> _PreparedLiveTLSVerification:
    """Validate all deterministic Stage-7 TLS configuration without connecting."""

    validate_live_tls_configuration(endpoint, readiness)
    if not isinstance(trusted_ca_data, bytes) or not trusted_ca_data:
        raise LiveTLSVerificationError("explicit UniFi TLS CA data is required")
    try:
        ca_pem = validate_installation_ca(trusted_ca_data)
        context = create_client_tls_context(ca_data=ca_pem)
    except (CertificateInspectionError, TLSConfigurationError):
        raise LiveTLSVerificationError(
            "invalid UniFi TLS trust configuration"
        ) from None
    return _PreparedLiveTLSVerification(endpoint, readiness, context)


def verify_prepared_live_tls_certificate(
    *, prepared: _PreparedLiveTLSVerification, expected_leaf_der: bytes
) -> str:
    """Connect using deterministic TLS configuration validated before mutation."""

    if not isinstance(prepared, _PreparedLiveTLSVerification):
        raise LiveTLSVerificationError("invalid prepared UniFi TLS verification")
    expected = _canonical_leaf(expected_leaf_der)
    endpoint = prepared.endpoint
    readiness = prepared.readiness
    context = prepared.context

    deadline = time.monotonic() + float(readiness.timeout_seconds)
    for attempt in range(readiness.max_attempts):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        attempt_deadline = min(
            deadline,
            time.monotonic() + float(readiness.attempt_timeout_seconds),
        )
        try:
            served = _connect_and_get_leaf(
                endpoint, context=context, deadline=attempt_deadline
            )
        except ssl.SSLCertVerificationError:
            raise TLSAuthenticationError(
                "UniFi TLS chain or hostname validation failed"
            ) from None
        except ssl.SSLError:
            raise TLSHandshakeError("UniFi TLS handshake failed") from None
        except (ConnectionError, TimeoutError, OSError):
            if attempt + 1 >= readiness.max_attempts:
                break
            delay = min(
                float(readiness.retry_delay_seconds),
                max(0.0, deadline - time.monotonic()),
            )
            if delay:
                time.sleep(delay)
            continue

        if served != expected:
            raise ServedCertificateMismatchError(
                "UniFi served certificate differs from the issued certificate"
            )
        return hashlib.sha256(served).hexdigest()

    raise EndpointNotReadyError(
        "UniFi TLS endpoint did not become ready within the bounded policy"
    )


def _connect_and_get_leaf(
    endpoint: LiveTLSEndpoint, *, context: ssl.SSLContext, deadline: float
) -> bytes:
    # The connection address is numeric by contract, avoiding an unbounded DNS
    # lookup outside the monotonic readiness deadline. TLS identity remains a
    # separately configured DNS name or IP address.
    family = (
        socket.AF_INET6 if ip_address(endpoint.address).version == 6 else socket.AF_INET
    )
    with socket.socket(family, socket.SOCK_STREAM) as raw:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        raw.settimeout(remaining)
        raw.connect((endpoint.address, endpoint.port))
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        raw.settimeout(remaining)
        with context.wrap_socket(
            raw, server_hostname=endpoint.server_hostname
        ) as connection:
            leaf = connection.getpeercert(binary_form=True)
    if not isinstance(leaf, bytes) or not 1 <= len(leaf) <= MAX_LEAF_DER_BYTES:
        raise TLSHandshakeError("UniFi TLS peer returned invalid certificate data")
    return leaf


def _canonical_leaf(value: bytes) -> bytes:
    if not isinstance(value, bytes) or not 1 <= len(value) <= MAX_LEAF_DER_BYTES:
        raise LiveTLSVerificationError("invalid expected UniFi certificate")
    try:
        canonical = x509.load_der_x509_certificate(value).public_bytes(Encoding.DER)
    except ValueError:
        raise LiveTLSVerificationError("invalid expected UniFi certificate") from None
    if canonical != value:
        raise LiveTLSVerificationError(
            "expected UniFi certificate is not canonical DER"
        )
    return canonical


def _validate_host(value: str, label: str) -> None:
    if not isinstance(value, str) or not value or len(value) > MAX_HOST_CHARS:
        raise LiveTLSVerificationError(f"invalid UniFi TLS {label}")
    if "%" in value:
        raise LiveTLSVerificationError(f"invalid UniFi TLS {label}")
    try:
        ip_address(value)
        return
    except ValueError:
        pass
    try:
        value.encode("ascii")
    except UnicodeEncodeError:
        raise LiveTLSVerificationError(f"invalid UniFi TLS {label}") from None
    name = value[:-1] if value.endswith(".") else value
    if not name or any(_DNS_LABEL.fullmatch(part) is None for part in name.split(".")):
        raise LiveTLSVerificationError(f"invalid UniFi TLS {label}")


def _validate_ip_address(value: str) -> None:
    if not isinstance(value, str) or not value or len(value) > MAX_HOST_CHARS:
        raise LiveTLSVerificationError("invalid UniFi TLS connection address")
    if "%" in value:
        raise LiveTLSVerificationError("invalid UniFi TLS connection address")
    try:
        ip_address(value)
    except ValueError:
        raise LiveTLSVerificationError(
            "UniFi TLS connection address must be numeric"
        ) from None
