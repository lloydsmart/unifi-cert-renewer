"""Protected public policy parser and source regressions."""

import hashlib
import json
import os
from dataclasses import replace
from datetime import timedelta
from types import SimpleNamespace

import pytest
from conftest import policy_for, public_der, public_pem
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

import renewal_policy
import unifi_executor_service as service
from csr import inspect_csr
from unifi_client import prepare_certificate_import


def value_for(material):
    policy = policy_for(material)
    return {
        "schema_version": 2,
        "subject": policy.subject,
        "dns_sans": list(policy.dns_sans),
        "ip_sans": list(policy.ip_sans),
        "issuing_ca_pem": public_pem(material.ca).decode(),
        "issuing_ca_description": policy.issuing_ca_description,
        "lifetime_days": policy.lifetime_days,
        "signing_digest": policy.signing_digest,
        "issued_signature_oid": policy.issued_signature_oid,
        "csr_signature_algorithm": policy.csr_signature_algorithm,
        "live_tls": {
            "address": policy.endpoint.address,
            "server_hostname": policy.endpoint.server_hostname,
            "port": policy.endpoint.port,
            "timeout_seconds": policy.readiness.timeout_seconds,
            "attempt_timeout_seconds": policy.readiness.attempt_timeout_seconds,
            "retry_delay_seconds": policy.readiness.retry_delay_seconds,
            "max_attempts": policy.readiness.max_attempts,
        },
    }


def test_exact_artifact_bytes_define_public_drift_digest(installation_material):
    value = value_for(installation_material)
    compact = json.dumps(value, separators=(",", ":")).encode()
    spaced = json.dumps(value, indent=2).encode()
    first = renewal_policy.parse_policy(compact)
    second = renewal_policy.parse_policy(spaced)
    assert first.digest == hashlib.sha256(compact).hexdigest()
    assert second.digest == hashlib.sha256(spaced).hexdigest()
    assert first.digest != second.digest
    assert first.ca_pem == second.ca_pem
    assert (
        first.certificate_policy(
            installation_material.request.policy.expected_spki_sha256
        )
        == installation_material.request.policy
    )


def _self_signed_ca(key, now, signature_hash):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic issuing CA")])
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=730))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
        .add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False),
            True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False
        )
        .sign(key, signature_hash)
    )


@pytest.fixture(scope="module")
def ec_issuing_ca(installation_material):
    key = ec.generate_private_key(ec.SECP384R1())
    certificate = _self_signed_ca(key, installation_material.now, hashes.SHA384())
    return key, certificate


@pytest.mark.parametrize(
    ("ca_key_type", "signing_digest", "expected_oid"),
    [
        ("RSA", "sha256", "1.2.840.113549.1.1.11"),
        ("RSA", "sha384", "1.2.840.113549.1.1.12"),
        ("RSA", "sha512", "1.2.840.113549.1.1.13"),
        ("EC", "sha256", "1.2.840.10045.4.3.2"),
        ("EC", "sha384", "1.2.840.10045.4.3.3"),
        ("EC", "sha512", "1.2.840.10045.4.3.4"),
    ],
)
def test_issued_signature_oid_uses_ca_public_key_and_signing_digest(
    installation_material, ec_issuing_ca, ca_key_type, signing_digest, expected_oid
):
    value = value_for(installation_material)
    ca = installation_material.ca if ca_key_type == "RSA" else ec_issuing_ca[1]
    value.update(
        issuing_ca_pem=public_pem(ca).decode(),
        signing_digest=signing_digest,
        issued_signature_oid=expected_oid,
    )

    parsed = renewal_policy.parse_policy(json.dumps(value).encode())

    assert parsed.signing_digest == signing_digest
    assert parsed.issued_signature_oid == expected_oid
    assert parsed.csr_signature_algorithm == "SHA384withRSA"


@pytest.mark.parametrize(
    ("ca_key_type", "signing_digest", "wrong_oid"),
    [
        ("EC", "sha256", "1.2.840.113549.1.1.11"),
        ("RSA", "sha256", "1.2.840.10045.4.3.2"),
        ("EC", "sha384", "1.2.840.10045.4.3.2"),
        ("RSA", "sha512", "1.2.840.113549.1.1.12"),
    ],
)
def test_issued_signature_oid_rejects_wrong_ca_type_or_digest(
    installation_material, ec_issuing_ca, ca_key_type, signing_digest, wrong_oid
):
    value = value_for(installation_material)
    ca = installation_material.ca if ca_key_type == "RSA" else ec_issuing_ca[1]
    value.update(
        issuing_ca_pem=public_pem(ca).decode(),
        signing_digest=signing_digest,
        issued_signature_oid=wrong_oid,
    )
    with pytest.raises(renewal_policy.PolicyError, match="invalid issued signature"):
        renewal_policy.parse_policy(json.dumps(value).encode())


def test_unsupported_ca_public_key_type_fails_closed(installation_material):
    key = dsa.generate_private_key(key_size=2048)
    ca = _self_signed_ca(key, installation_material.now, hashes.SHA256())
    value = value_for(installation_material)
    value["issuing_ca_pem"] = public_pem(ca).decode()

    with pytest.raises(renewal_policy.PolicyError, match="unsupported issuing CA"):
        renewal_policy.parse_policy(json.dumps(value).encode())


def test_ca_self_signature_digest_does_not_select_leaf_signature_oid(
    installation_material, ec_issuing_ca
):
    key, first_ca = ec_issuing_ca
    second_ca = _self_signed_ca(key, installation_material.now, hashes.SHA512())
    assert first_ca.signature_hash_algorithm.name == "sha384"
    assert second_ca.signature_hash_algorithm.name == "sha512"
    for ca in (first_ca, second_ca):
        value = value_for(installation_material)
        value.update(
            issuing_ca_pem=public_pem(ca).decode(),
            signing_digest="sha256",
            issued_signature_oid="1.2.840.10045.4.3.2",
        )
        parsed = renewal_policy.parse_policy(json.dumps(value).encode())
        assert parsed.issued_signature_oid == "1.2.840.10045.4.3.2"


@pytest.fixture(scope="module")
def rsa_4096_unifi_material(installation_material):
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    material = replace(installation_material, key=key)
    old_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "unifi")])
    old = (
        x509.CertificateBuilder()
        .subject_name(old_name)
        .issuer_name(old_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(material.now - timedelta(days=365))
        .not_valid_after(material.now + timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    csr_pem = material.make_csr()
    material.request = replace(
        material.request,
        before=replace(
            material.request.before, certificate_chain_der=(public_der(old),)
        ),
        policy=replace(
            material.request.policy,
            expected_spki_sha256=inspect_csr(csr_pem).spki_sha256,
        ),
        csr_pem=csr_pem,
    )
    return material


def _ec_issued_leaf(material, ca_key, ca, signature_hash):
    return (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "unifi.test")])
        )
        .issuer_name(ca.subject)
        .public_key(material.key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(material.now - timedelta(minutes=1))
        .not_valid_after(material.now + timedelta(days=30, minutes=-1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
        .add_extension(
            x509.KeyUsage(True, False, True, False, False, False, False, False, False),
            True,
        )
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("unifi.test")]), False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            False,
        )
        .sign(ca_key, signature_hash)
    )


def _ec_sha256_policy(material, ca):
    value = value_for(material)
    value.update(
        issuing_ca_pem=public_pem(ca).decode(),
        issuing_ca_description="Synthetic issuing CA",
        signing_digest="sha256",
        issued_signature_oid="1.2.840.10045.4.3.2",
    )
    return value


def test_rsa_unifi_csr_and_ec_ca_leaf_pass_v2_executor_policy_validation(
    rsa_4096_unifi_material, ec_issuing_ca
):
    material = rsa_4096_unifi_material
    ca_key, ca = ec_issuing_ca
    csr = inspect_csr(material.request.csr_pem)
    assert csr.public_key_algorithm == "RSA"
    assert csr.public_key_size == 4096
    assert csr.signature_hash_algorithm == "sha384"
    assert csr.signature_algorithm_oid == "1.2.840.113549.1.1.12"

    leaf = _ec_issued_leaf(material, ca_key, ca, hashes.SHA256())
    assert leaf.signature_algorithm_oid.dotted_string == "1.2.840.10045.4.3.2"

    value = _ec_sha256_policy(material, ca)
    policy = renewal_policy.parse_policy(json.dumps(value).encode())
    assert policy.csr_signature_algorithm == "SHA384withRSA"
    public_request = replace(material.request, issued_certificate=public_pem(leaf))
    decoded = service._decode_import_request(
        service._encode_import_request(public_request), policy
    )
    plan = prepare_certificate_import(decoded)
    assert decoded.policy == material.request.policy
    assert decoded.trusted_ca_data == policy.ca_pem
    assert decoded.expected_signature_hash == policy.signing_digest
    assert decoded.expected_signature_oid == policy.issued_signature_oid
    assert set(service._encode_import_request(public_request)) == {
        "before",
        "csr_pem",
        "issued_certificate",
    }
    assert plan.issued.signature_hash_algorithm == "sha256"
    assert plan.issued.signature_algorithm_oid == policy.issued_signature_oid

    value["csr_signature_algorithm"] = "SHA384withECDSA"
    with pytest.raises(renewal_policy.PolicyError, match="invalid CSR signature"):
        renewal_policy.parse_policy(json.dumps(value).encode())


def test_trusted_ec_sha384_leaf_rejected_by_sha256_executor_policy(
    rsa_4096_unifi_material, ec_issuing_ca
):
    material = rsa_4096_unifi_material
    ca_key, ca = ec_issuing_ca
    policy = renewal_policy.parse_policy(
        json.dumps(_ec_sha256_policy(material, ca)).encode()
    )
    leaf = _ec_issued_leaf(material, ca_key, ca, hashes.SHA384())
    assert leaf.signature_algorithm_oid.dotted_string == "1.2.840.10045.4.3.3"
    assert leaf.signature_hash_algorithm.name == "sha384"

    request = replace(
        material.request,
        issued_certificate=public_pem(leaf),
        trusted_ca_data=policy.ca_pem,
    )
    with pytest.raises(ValueError, match="signature differs"):
        prepare_certificate_import(request)

    with pytest.raises(ValueError):
        service._decode_import_request(service._encode_import_request(request), policy)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value.update(schema_version=1),
        lambda value: value.update(unknown="x"),
        lambda value: value.update(subject="bad\nsubject"),
        lambda value: value.update(subject=False),
        lambda value: value.update(dns_sans=["unifi.test", "unifi.test"]),
        lambda value: value.update(dns_sans=[], ip_sans=[]),
        lambda value: value.update(dns_sans="unifi.test"),
        lambda value: value.update(ip_sans=["not-an-ip"]),
        lambda value: value.update(issuing_ca_pem="not a CA"),
        lambda value: value.update(lifetime_days=True),
        lambda value: value.update(lifetime_days=398),
        lambda value: value.update(signing_digest="sha1"),
        lambda value: value.update(issued_signature_oid="1.2.840.113549.1.1.12"),
        lambda value: value.update(csr_signature_algorithm="SHA256withRSA"),
        lambda value: value["live_tls"].update(address="unifi.test"),
        lambda value: value["live_tls"].update(server_hostname="bad\nhost"),
        lambda value: value["live_tls"].update(port=0),
        lambda value: value["live_tls"].update(timeout_seconds=121),
        lambda value: value["live_tls"].update(max_attempts=True),
        lambda value: value["live_tls"].update(extra="unknown"),
    ],
)
def test_invalid_policy_fails_closed(installation_material, mutate):
    value = value_for(installation_material)
    mutate(value)
    with pytest.raises(renewal_policy.PolicyError):
        renewal_policy.parse_policy(json.dumps(value).encode())


def test_malformed_duplicate_and_oversize_artifacts_fail(installation_material):
    value = value_for(installation_material)
    valid = json.dumps(value).encode()
    for data in (
        b"{",
        b'{"schema_version":2,"schema_version":2}',
        valid[:-1] + b',"unknown":1}',
        b"x" * (renewal_policy.MAX_POLICY_BYTES + 1),
    ):
        with pytest.raises(renewal_policy.PolicyError):
            renewal_policy.parse_policy(data)


def _root_owned_stat(original):
    def fstat(descriptor):
        info = original(descriptor)
        return SimpleNamespace(
            st_mode=info.st_mode,
            st_uid=0,
            st_dev=info.st_dev,
            st_ino=info.st_ino,
            st_size=info.st_size,
            st_nlink=info.st_nlink,
            st_mtime_ns=info.st_mtime_ns,
        )

    return fstat


def test_policy_source_requires_trusted_root_file_and_no_symlink(
    installation_material, tmp_path, monkeypatch
):
    directory = tmp_path / "policy"
    directory.mkdir(mode=0o755)
    document = directory / renewal_policy.POLICY_NAME
    document.write_bytes(json.dumps(value_for(installation_material)).encode())
    document.chmod(0o444)
    monkeypatch.setattr(renewal_policy, "POLICY_DIRECTORY", str(directory))
    with monkeypatch.context() as patch:
        patch.setattr(renewal_policy.os, "fstat", _root_owned_stat(os.fstat))
        assert (
            renewal_policy.load_policy().digest
            == hashlib.sha256(document.read_bytes()).hexdigest()
        )
        document.chmod(0o664)
        with pytest.raises(renewal_policy.PolicyError):
            renewal_policy.load_policy()
        document.chmod(0o444)
        directory.chmod(0o777)
        with pytest.raises(renewal_policy.PolicyError):
            renewal_policy.load_policy()
        directory.chmod(0o755)
        document.rename(directory / "real.json")
        document.symlink_to("real.json")
        with pytest.raises(renewal_policy.PolicyError):
            renewal_policy.load_policy()
    with pytest.raises(renewal_policy.PolicyError):
        renewal_policy.load_policy()


def test_executor_service_rejects_invalid_policy_before_listening(monkeypatch):
    def invalid():
        raise renewal_policy.PolicyError("invalid policy")

    monkeypatch.setattr(service, "load_policy", invalid)
    with pytest.raises(renewal_policy.PolicyError):
        service._ProtocolHandler()


def test_ca_rollover_changes_authority_and_rejects_old_issued_leaf(
    installation_material,
):
    material = installation_material
    value = value_for(material)
    old = renewal_policy.parse_policy(json.dumps(value).encode())
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca = (
        x509.CertificateBuilder()
        .subject_name(material.ca.subject)
        .issuer_name(material.ca.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(material.now - timedelta(days=1))
        .not_valid_after(material.now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
        .add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False),
            True,
        )
        .sign(key, hashes.SHA256())
    )
    value["issuing_ca_pem"] = public_pem(ca).decode()
    rotated = renewal_policy.parse_policy(json.dumps(value).encode())
    assert rotated.digest != old.digest
    assert rotated.ca_pem != old.ca_pem
    request = service._encode_import_request(material.request)
    with pytest.raises(ValueError):
        service._decode_import_request(request, rotated)


def test_policy_verification_deadline_fits_socket_response_budget():
    from unifi_executor_client import SOCKET_TIMEOUT_SECONDS

    assert renewal_policy.MAX_VERIFICATION_SECONDS < SOCKET_TIMEOUT_SECONDS


def test_production_shaped_397_day_leaf_passes_common_and_executor_policy(
    rsa_4096_unifi_material, ec_issuing_ca
):
    material = rsa_4096_unifi_material
    ca_key, ca = ec_issuing_ca
    not_before = material.now
    leaf = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "unifi.test")])
        )
        .issuer_name(ca.subject)
        .public_key(material.key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_before + timedelta(days=397))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        .add_extension(
            x509.ExtendedKeyUsage(
                [
                    ExtendedKeyUsageOID.SERVER_AUTH,
                    x509.ObjectIdentifier("1.3.6.1.5.5.8.2.2"),
                ]
            ),
            False,
        )
        .add_extension(
            x509.KeyUsage(True, False, True, False, False, False, False, False, False),
            True,
        )
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("unifi.test")]), False)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(material.key.public_key()), False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            False,
        )
        .add_extension(
            x509.UnrecognizedExtension(
                x509.ObjectIdentifier("2.16.840.1.113730.1.1"), b"\x03\x02\x00\x40"
            ),
            False,
        )
        .add_extension(
            x509.UnrecognizedExtension(
                x509.ObjectIdentifier("2.16.840.1.113730.1.13"), b"\x16\x06stock!"
            ),
            False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    value = _ec_sha256_policy(material, ca)
    value["lifetime_days"] = 397
    policy = renewal_policy.parse_policy(json.dumps(value).encode())
    request = replace(
        material.request,
        issued_certificate=public_pem(leaf),
        trusted_ca_data=policy.ca_pem,
        lifetime_days=397,
        expected_signature_hash=policy.signing_digest,
        expected_signature_oid=policy.issued_signature_oid,
        freshness_reference_time=material.now,
    )
    direct = prepare_certificate_import(request)
    decoded = service._decode_import_request(
        service._encode_import_request(request), policy
    )
    assert prepare_certificate_import(decoded).issued == direct.issued
    assert direct.issued.public_key_size == 4096
    assert direct.issued.signature_algorithm_oid == "1.2.840.10045.4.3.2"
    assert direct.issued.not_valid_after - direct.issued.not_valid_before == timedelta(
        days=397
    )


@pytest.mark.parametrize("hash_algorithm", [hashes.SHA384(), hashes.SHA512()])
def test_worker_and_executor_reject_other_sha2_issued_digest(
    rsa_4096_unifi_material, ec_issuing_ca, hash_algorithm
):
    material = rsa_4096_unifi_material
    ca_key, ca = ec_issuing_ca
    policy = renewal_policy.parse_policy(
        json.dumps(_ec_sha256_policy(material, ca)).encode()
    )
    leaf = _ec_issued_leaf(material, ca_key, ca, hash_algorithm)
    request = replace(
        material.request,
        issued_certificate=public_pem(leaf),
        trusted_ca_data=policy.ca_pem,
        expected_signature_hash=policy.signing_digest,
        expected_signature_oid=policy.issued_signature_oid,
    )
    with pytest.raises(ValueError, match="signature differs"):
        prepare_certificate_import(request)
    with pytest.raises(ValueError):
        service._decode_import_request(service._encode_import_request(request), policy)


def test_worker_cannot_override_signature_policy_on_protocol_v2(
    installation_material,
):
    policy = policy_for(installation_material)
    altered = replace(
        installation_material.request,
        expected_signature_hash="sha512",
        expected_signature_oid="1.2.840.113549.1.1.13",
    )
    wire = service._encode_import_request(altered)
    assert set(wire) == {"before", "csr_pem", "issued_certificate"}
    decoded = service._decode_import_request(wire, policy)
    assert decoded.expected_signature_hash == policy.signing_digest
    assert decoded.expected_signature_oid == policy.issued_signature_oid
