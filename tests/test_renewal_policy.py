"""Protected public policy parser and source regressions."""

import hashlib
import json
import os
from datetime import timedelta
from types import SimpleNamespace

import pytest
from conftest import policy_for, public_pem
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa

import renewal_policy
import unifi_executor_service as service


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
