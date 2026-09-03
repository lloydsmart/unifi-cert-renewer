import ssl
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from tls_policy import (
    MAX_TLS_CA_FILE_BYTES,
    TLSConfigurationError,
    create_client_tls_context,
)


def test_context_requires_verified_tls_1_2_or_newer() -> None:
    context = create_client_tls_context()

    assert context.minimum_version == ssl.TLSVersion.TLSv1_2
    assert context.maximum_version == ssl.TLSVersion.MAXIMUM_SUPPORTED
    assert context.check_hostname is True
    assert context.verify_mode == ssl.CERT_REQUIRED


def test_context_loads_configured_public_ca(tmp_path) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    ca_file = tmp_path / "ca.pem"
    ca_file.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    ca_file.chmod(0o644)

    context = create_client_tls_context(cafile=str(ca_file))

    assert context.cert_store_stats()["x509_ca"] == 1


def test_context_rejects_unsafe_or_oversized_ca_file(tmp_path) -> None:
    ca_file = tmp_path / "ca.pem"
    ca_file.write_bytes(b"not a CA")
    ca_file.chmod(0o602)

    with pytest.raises(TLSConfigurationError, match="world-writable"):
        create_client_tls_context(cafile=str(ca_file))

    ca_file.write_bytes(b"x" * (MAX_TLS_CA_FILE_BYTES + 1))
    ca_file.chmod(0o600)
    with pytest.raises(TLSConfigurationError, match="size limit"):
        create_client_tls_context(cafile=str(ca_file))
