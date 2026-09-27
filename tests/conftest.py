import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from csr import inspect_csr
from renewal_policy import parse_policy
from unifi_client import (
    CertificateImportRequest,
    CertificatePolicy,
    PublicKeystoreState,
)


def public_pem(value):
    return value.public_bytes(serialization.Encoding.PEM)


def public_der(value):
    return value.public_bytes(serialization.Encoding.DER)


def metadata(length=1):
    return (
        "Keystore type: PKCS12\nKeystore provider: SUN\n"
        "Alias name: unifi\nEntry type: PrivateKeyEntry\n"
        f"Certificate chain length: {length}\n"
    )


@dataclass
class InstallationMaterial:
    key: rsa.RSAPrivateKey
    ca_key: rsa.RSAPrivateKey
    ca: x509.Certificate
    request: CertificateImportRequest
    now: datetime

    def make_csr(self, *, key=None, subject="unifi.test", sans=None):
        return public_pem(
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
            .add_extension(
                x509.SubjectAlternativeName(
                    sans if sans is not None else [x509.DNSName("unifi.test")]
                ),
                critical=False,
            )
            .sign(key or self.key, hashes.SHA384())
        )

    def issue(
        self,
        *,
        key=None,
        subject="unifi.test",
        sans=None,
        ca=False,
        not_before=None,
        not_after=None,
        issuer=None,
        signing_key=None,
        signing_hash=None,
    ):
        return (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
            .issuer_name(issuer or self.ca.subject)
            .public_key((key or self.key).public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before or self.now - timedelta(minutes=1))
            .not_valid_after(not_after or self.now + timedelta(days=30, minutes=-1))
            .add_extension(
                x509.BasicConstraints(ca=ca, path_length=None), critical=True
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False
            )
            .add_extension(
                x509.SubjectAlternativeName(
                    sans if sans is not None else [x509.DNSName("unifi.test")]
                ),
                False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    self.ca_key.public_key()
                ),
                False,
            )
            .sign(signing_key or self.ca_key, signing_hash or hashes.SHA256())
        )


@pytest.fixture(scope="module")
def installation_material():
    now = datetime.now(UTC).replace(microsecond=0)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test root")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
        .add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False),
            True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), False
        )
        .sign(ca_key, hashes.SHA256())
    )
    material = InstallationMaterial(key, ca_key, ca, None, now)
    old_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "unifi")])
    old = (
        x509.CertificateBuilder()
        .subject_name(old_name)
        .issuer_name(old_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=365))
        .not_valid_after(now + timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    csr_pem = material.make_csr()
    policy = CertificatePolicy(
        inspect_csr(csr_pem).spki_sha256, "CN=unifi.test", ("unifi.test",)
    )
    material.request = CertificateImportRequest(
        PublicKeystoreState(metadata(), (public_der(old),)),
        policy,
        csr_pem,
        public_pem(material.issue()),
        public_pem(ca),
        30,
    )
    return material


def policy_for(material, *, port=8443, timeout=2):
    """Generated public policy matching the disposable signing material."""
    request = material.request
    value = {
        "schema_version": 2,
        "subject": request.policy.subject,
        "dns_sans": list(request.policy.dns_sans),
        "ip_sans": list(request.policy.ip_sans),
        "issuing_ca_pem": public_pem(material.ca).decode("ascii"),
        "issuing_ca_description": "Test root",
        "lifetime_days": request.lifetime_days,
        "signing_digest": "sha256",
        "issued_signature_oid": "1.2.840.113549.1.1.11",
        "csr_signature_algorithm": "SHA384withRSA",
        "live_tls": {
            "address": "127.0.0.1",
            "server_hostname": "unifi.test",
            "port": port,
            "timeout_seconds": timeout,
            "attempt_timeout_seconds": min(timeout, 1),
            "retry_delay_seconds": 0,
            "max_attempts": 2,
        },
    }
    return parse_policy(json.dumps(value).encode())
