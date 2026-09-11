import hashlib
import os
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


def _memory_file(data):
    if not hasattr(os, "memfd_create") or not os.path.isdir("/proc/self/fd"):
        pytest.skip("memory-backed TLS fixture files require Linux memfd_create")
    descriptor = os.memfd_create("unifi-cert-renewer-test", os.MFD_CLOEXEC)
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise RuntimeError("could not prepare memory-backed TLS fixture")
            view = view[written:]
        os.lseek(descriptor, 0, os.SEEK_SET)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _server_context(certificate, key):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    # Python's SSL API requires paths. Linux memfd keeps generated test key bytes
    # off the filesystem; /proc exposes each descriptor only while OpenSSL loads it.
    certificate_fd = None
    key_fd = None
    try:
        certificate_fd = _memory_file(public_pem(certificate))
        key_fd = _memory_file(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        context.load_cert_chain(
            f"/proc/self/fd/{certificate_fd}",
            f"/proc/self/fd/{key_fd}",
        )
    finally:
        for descriptor in (certificate_fd, key_fd):
            if descriptor is not None:
                os.close(descriptor)
    return context


def test_server_context_leaves_no_private_key_artifact(installation_material, tmp_path):
    material = installation_material
    _server_context(material.issue(), material.key)
    assert list(tmp_path.iterdir()) == []


def _serve_once(context, *, raw=False, delay=0.0, stall=0.0):
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
                if stall:
                    time.sleep(stall)
                elif raw:
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


@pytest.mark.parametrize("encoding", ["PEM", "DER"])
def test_direct_verifier_accepts_equivalent_ca_encodings(
    installation_material, encoding
):
    material = installation_material
    leaf = material.issue()
    context = _server_context(leaf, material.key)
    port, thread = _serve_once(context)

    fingerprint = verify_live_tls_certificate(
        endpoint=LiveTLSEndpoint("127.0.0.1", "unifi.test", port),
        readiness=ReadinessPolicy(2, 1, 0.01, 20),
        trusted_ca_data=(
            public_pem(material.ca) if encoding == "PEM" else public_der(material.ca)
        ),
        expected_leaf_der=public_der(leaf),
    )

    thread.join(2)
    assert fingerprint == hashlib.sha256(public_der(leaf)).hexdigest()


def test_connection_refused_then_real_tls_becomes_ready(installation_material):
    material = installation_material
    leaf = material.issue()
    context = _server_context(leaf, material.key)
    port, thread = _serve_once(context, delay=0.05)

    assert _verify(material, port, leaf) == hashlib.sha256(public_der(leaf)).hexdigest()
    thread.join(2)


def test_real_tls_verifies_ip_identity(installation_material):
    material = installation_material
    leaf = material.issue(sans=[x509.IPAddress(ip_address("127.0.0.1"))])
    context = _server_context(leaf, material.key)
    port, thread = _serve_once(context)
    result = verify_live_tls_certificate(
        endpoint=LiveTLSEndpoint("127.0.0.1", "127.0.0.1", port),
        readiness=ReadinessPolicy(2, 1, 0, 1),
        trusted_ca_data=public_pem(material.ca),
        expected_leaf_der=public_der(leaf),
    )
    thread.join(2)
    assert result == hashlib.sha256(public_der(leaf)).hexdigest()


def test_real_tls_sends_configured_sni(installation_material):
    material = installation_material
    leaf = material.issue()
    context = _server_context(leaf, material.key)
    observed = []

    def record_sni(connection, server_name, selected_context):
        observed.append(server_name)

    context.set_servername_callback(record_sni)
    port, thread = _serve_once(context)
    _verify(material, port, leaf)
    thread.join(2)
    assert observed == ["unifi.test"]


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


def test_real_tls_handshake_failure_is_not_readiness_retry(installation_material):
    material = installation_material
    leaf = material.issue()
    context = _server_context(leaf, material.key)
    port, thread = _serve_once(context, raw=True)
    with pytest.raises(TLSHandshakeError):
        _verify(material, port, leaf)
    thread.join(2)


def test_real_stalled_handshake_is_deadline_bounded(installation_material):
    material = installation_material
    leaf = material.issue()
    context = _server_context(leaf, material.key)
    port, thread = _serve_once(context, stall=0.25)
    started = time.monotonic()
    with pytest.raises(EndpointNotReadyError):
        verify_live_tls_certificate(
            endpoint=LiveTLSEndpoint("127.0.0.1", "unifi.test", port),
            readiness=ReadinessPolicy(0.2, 0.1, 0, 1),
            trusted_ca_data=public_pem(material.ca),
            expected_leaf_der=public_der(leaf),
        )
    elapsed = time.monotonic() - started
    thread.join(1)
    assert elapsed < 0.5


@pytest.mark.parametrize("failure", ["untrusted", "hostname"])
def test_real_tls_authentication_failures(installation_material, failure):
    material = installation_material
    leaf = (
        material.issue(subject="other.test", sans=[x509.DNSName("other.test")])
        if failure == "hostname"
        else material.issue()
    )
    context = _server_context(leaf, material.key)
    port, thread = _serve_once(context)
    trusted = public_pem(material.ca)
    if failure == "untrusted":
        other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        other_name = x509.Name(
            [x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "Other test root")]
        )
        other = material.issue(
            key=other_key,
            subject="Other test root",
            ca=True,
            issuer=other_name,
            signing_key=other_key,
        )
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
    installation_material, kind
):
    material = installation_material
    expected = material.issue()
    key = material.key
    if kind == "other-key":
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    served = material.issue(key=key)
    context = _server_context(served, key)
    port, thread = _serve_once(context)
    with pytest.raises(ServedCertificateMismatchError, match="differs"):
        _verify(material, port, expected)
    thread.join(2)


def test_previous_self_signed_leaf_fails_authentication(installation_material):
    material = installation_material
    previous = material.request.before.certificate_chain_der[0]
    # The fixture's old leaf is self-signed with the same private key.
    old = x509.load_der_x509_certificate(previous)
    context = _server_context(old, material.key)
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


@pytest.mark.parametrize("trusted_ca_data", [None, b""])
def test_explicit_ca_is_required_before_socket_activity(
    installation_material, monkeypatch, trusted_ca_data
):
    socket_called = False
    context_called = False

    def forbidden_socket(*args, **kwargs):
        nonlocal socket_called
        socket_called = True
        raise AssertionError("socket must not be created")

    def forbidden_context(*args, **kwargs):
        nonlocal context_called
        context_called = True
        raise AssertionError("TLS context must not be created")

    monkeypatch.setattr(unifi_tls.socket, "socket", forbidden_socket)
    monkeypatch.setattr(unifi_tls, "create_client_tls_context", forbidden_context)
    expected = prepare_certificate_import(
        installation_material.request
    ).certificate_chain_der[0]
    with pytest.raises(LiveTLSVerificationError, match="explicit"):
        verify_live_tls_certificate(
            endpoint=LiveTLSEndpoint("127.0.0.1", "unifi.test"),
            readiness=ReadinessPolicy(1, 1, 0, 1),
            trusted_ca_data=trusted_ca_data,
            expected_leaf_der=expected,
        )
    assert socket_called is False
    assert context_called is False
