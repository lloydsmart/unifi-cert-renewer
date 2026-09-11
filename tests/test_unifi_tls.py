import hashlib
import socket
import ssl
import threading
import time
from contextlib import closing
from dataclasses import replace
from ipaddress import ip_address

import pytest
from conftest import public_der, public_pem
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import unifi_tls
from unifi_client import prepare_certificate_import
from unifi_tls import (
    EndpointNotReadyError,
    LiveTLSEndpoint,
    LiveTLSVerificationError,
    ReadinessPolicy,
    ServedCertificateMismatchError,
    TLSAuthenticationError,
    TLSHandshakeError,
    verify_live_tls_certificate,
)


def _server_context(tmp_path, certificate, key):
    certificate_path = tmp_path / f"{certificate.serial_number}.pem"
    key_path = tmp_path / f"{certificate.serial_number}.key"
    certificate_path.write_bytes(public_pem(certificate))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    key_path.chmod(0o600)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certificate_path, key_path)
    return context


def _serve_once(context, *, raw=False, delay=0.0):
    reservation = socket.socket()
    reservation.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    reservation.bind(("127.0.0.1", 0))
    port = reservation.getsockname()[1]
    if not delay:
        reservation.listen()

    def serve():
        listener = reservation
        try:
            if delay:
                time.sleep(delay)
                listener.listen()
            listener.settimeout(2)
            connection, _ = listener.accept()
            with connection:
                if raw:
                    connection.sendall(b"not a TLS endpoint")
                else:
                    try:
                        with context.wrap_socket(connection, server_side=True):
                            pass
                    except ssl.SSLError:
                        pass
        except OSError:
            pass
        finally:
            listener.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return port, thread


def _verify(material, port, leaf):
    return verify_live_tls_certificate(
        endpoint=LiveTLSEndpoint("127.0.0.1", "unifi.test", port),
        readiness=ReadinessPolicy(2, 1, 0.01, 20),
        trusted_ca_data=public_pem(material.ca),
        expected_leaf_der=public_der(leaf),
    )


def test_real_tls_serves_exact_issued_leaf(installation_material, tmp_path):
    material = installation_material
    leaf = material.issue()
    context = _server_context(tmp_path, leaf, material.key)
    port, thread = _serve_once(context)

    fingerprint = _verify(material, port, leaf)

    thread.join(2)
    assert fingerprint == hashlib.sha256(public_der(leaf)).hexdigest()


def test_connection_refused_then_real_tls_becomes_ready(
    installation_material, tmp_path
):
    material = installation_material
    leaf = material.issue()
    context = _server_context(tmp_path, leaf, material.key)
    port, thread = _serve_once(context, delay=0.05)

    assert _verify(material, port, leaf) == hashlib.sha256(public_der(leaf)).hexdigest()
    thread.join(2)


def test_real_tls_verifies_ip_identity(installation_material, tmp_path):
    material = installation_material
    leaf = material.issue(sans=[x509.IPAddress(ip_address("127.0.0.1"))])
    context = _server_context(tmp_path, leaf, material.key)
    port, thread = _serve_once(context)
    result = verify_live_tls_certificate(
        endpoint=LiveTLSEndpoint("127.0.0.1", "127.0.0.1", port),
        readiness=ReadinessPolicy(2, 1, 0, 1),
        trusted_ca_data=public_pem(material.ca),
        expected_leaf_der=public_der(leaf),
    )
    thread.join(2)
    assert result == hashlib.sha256(public_der(leaf)).hexdigest()


def test_endpoint_never_becomes_ready_is_attempt_bounded(installation_material):
    with closing(socket.socket()) as unavailable:
        unavailable.bind(("127.0.0.1", 0))
        endpoint = LiveTLSEndpoint(
            "127.0.0.1", "unifi.test", unavailable.getsockname()[1]
        )
        with pytest.raises(EndpointNotReadyError, match="bounded"):
            verify_live_tls_certificate(
                endpoint=endpoint,
                readiness=ReadinessPolicy(5, 0.1, 0, 3),
                trusted_ca_data=public_pem(installation_material.ca),
                expected_leaf_der=prepare_certificate_import(
                    installation_material.request
                ).certificate_chain_der[0],
            )


def test_deadline_bounds_attempt_time_and_sleep(installation_material, monkeypatch):
    now = 0.0
    observed = []

    def clock():
        return now

    def connect(endpoint, *, context, deadline):
        nonlocal now
        observed.append(deadline - now)
        now = deadline
        raise TimeoutError

    def sleep(delay):
        nonlocal now
        now += delay

    monkeypatch.setattr(unifi_tls.time, "monotonic", clock)
    monkeypatch.setattr(unifi_tls.time, "sleep", sleep)
    monkeypatch.setattr(unifi_tls, "_connect_and_get_leaf", connect)
    with pytest.raises(EndpointNotReadyError):
        verify_live_tls_certificate(
            endpoint=LiveTLSEndpoint("127.0.0.1", "unifi.test"),
            readiness=ReadinessPolicy(1, 0.4, 0.1, 10),
            trusted_ca_data=public_pem(installation_material.ca),
            expected_leaf_der=prepare_certificate_import(
                installation_material.request
            ).certificate_chain_der[0],
        )
    assert observed == [0.4, 0.4]
    assert now == pytest.approx(1.0)


def test_connection_reset_is_retried_before_authentication(
    installation_material, monkeypatch
):
    expected = prepare_certificate_import(
        installation_material.request
    ).certificate_chain_der[0]
    attempts = 0

    def connect(endpoint, *, context, deadline):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise ConnectionResetError
        return expected

    monkeypatch.setattr(unifi_tls, "_connect_and_get_leaf", connect)
    result = verify_live_tls_certificate(
        endpoint=LiveTLSEndpoint("127.0.0.1", "unifi.test"),
        readiness=ReadinessPolicy(1, 0.5, 0, 2),
        trusted_ca_data=public_pem(installation_material.ca),
        expected_leaf_der=expected,
    )
    assert result == hashlib.sha256(expected).hexdigest()
    assert attempts == 2


def test_real_tls_handshake_failure_is_not_readiness_retry(
    installation_material, tmp_path
):
    material = installation_material
    leaf = material.issue()
    context = _server_context(tmp_path, leaf, material.key)
    port, thread = _serve_once(context, raw=True)
    with pytest.raises(TLSHandshakeError):
        _verify(material, port, leaf)
    thread.join(2)


@pytest.mark.parametrize("failure", ["untrusted", "hostname"])
def test_real_tls_authentication_failures(installation_material, tmp_path, failure):
    material = installation_material
    leaf = (
        material.issue(subject="other.test", sans=[x509.DNSName("other.test")])
        if failure == "hostname"
        else material.issue()
    )
    context = _server_context(tmp_path, leaf, material.key)
    port, thread = _serve_once(context)
    trusted = public_pem(material.ca)
    if failure == "untrusted":
        other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        other = material.issue(key=other_key)
        trusted = public_pem(other)
    with pytest.raises(TLSAuthenticationError, match="chain or hostname"):
        verify_live_tls_certificate(
            endpoint=LiveTLSEndpoint("127.0.0.1", "unifi.test", port),
            readiness=ReadinessPolicy(2, 1, 0, 2),
            trusted_ca_data=trusted,
            expected_leaf_der=public_der(leaf),
        )
    thread.join(2)


@pytest.mark.parametrize("kind", ["other-key", "same-spki", "exact-der"])
def test_authenticated_but_different_leaf_fails_immediately(
    installation_material, tmp_path, kind
):
    material = installation_material
    expected = material.issue()
    key = material.key
    if kind == "other-key":
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    served = material.issue(key=key)
    context = _server_context(tmp_path, served, key)
    port, thread = _serve_once(context)
    with pytest.raises(ServedCertificateMismatchError, match="differs"):
        _verify(material, port, expected)
    thread.join(2)


def test_previous_self_signed_leaf_fails_authentication(
    installation_material, tmp_path
):
    material = installation_material
    previous = material.request.before.certificate_chain_der[0]
    # The fixture's old leaf is self-signed with the same private key.
    old = x509.load_der_x509_certificate(previous)
    context = _server_context(tmp_path, old, material.key)
    port, thread = _serve_once(context)
    with pytest.raises(TLSAuthenticationError):
        _verify(material, port, material.issue())
    thread.join(2)


@pytest.mark.parametrize(
    "endpoint",
    [
        LiveTLSEndpoint("bad\nsecret", "unifi.test"),
        LiveTLSEndpoint("127.0.0.1", "bad\x1bsecret"),
        replace(LiveTLSEndpoint("127.0.0.1", "unifi.test"), port=0),
    ],
)
def test_invalid_endpoint_is_rejected_without_echo(endpoint):
    with pytest.raises(LiveTLSVerificationError) as raised:
        verify_live_tls_certificate(
            endpoint=endpoint,
            readiness=ReadinessPolicy(),
            trusted_ca_data=b"secret-ca-diagnostic",
            expected_leaf_der=b"secret-leaf-diagnostic",
        )
    assert "secret" not in str(raised.value)


def test_certificate_and_trust_inputs_are_size_bounded(installation_material):
    expected = prepare_certificate_import(
        installation_material.request
    ).certificate_chain_der[0]
    arguments = {
        "endpoint": LiveTLSEndpoint("127.0.0.1", "unifi.test"),
        "readiness": ReadinessPolicy(1, 1, 0, 1),
        "trusted_ca_data": public_pem(installation_material.ca),
        "expected_leaf_der": expected,
    }
    with pytest.raises(LiveTLSVerificationError):
        verify_live_tls_certificate(
            **{**arguments, "expected_leaf_der": b"x" * (64 * 1024 + 1)}
        )
    with pytest.raises(LiveTLSVerificationError):
        verify_live_tls_certificate(
            **{**arguments, "trusted_ca_data": b"x" * (256 * 1024 + 1)}
        )
