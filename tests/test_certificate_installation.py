import base64
import traceback
from contextlib import contextmanager
from dataclasses import replace
from datetime import timedelta
from functools import partial
from unittest.mock import Mock

import pytest
from conftest import metadata, public_der, public_pem
from cryptography import x509

from certificate import MAX_ISSUED_CERTIFICATE_BYTES, MAX_TRUST_BUNDLE_BYTES
from unifi_client import (
    MAX_KEYTOOL_OUTPUT_CHARS,
    CertificateImportPlan,
    PublicKeystoreState,
    UnifiClient,
    UnifiOperationError,
    build_keytool_importcert_command,
    prepare_certificate_import,
    verify_certificate_import,
)


class FakeBoundary:
    def __init__(self, request):
        self.request = request
        self.current = request.before
        self.events = []
        self.status = 0
        self.failure = None
        self.after = None
        self.locked = False

    @contextmanager
    def exclusive(self):
        self.events.append("lock")
        self.locked = True
        try:
            yield
        finally:
            self.locked = False
            self.events.append("unlock")

    def inspect_public_state(self):
        self.events.append("inspect")
        return self.current

    def generate_csr(self, argv):
        self.events.append("csr")
        assert argv[0] == "/usr/bin/keytool"
        assert argv[1] == "-certreq"
        assert argv[-2:] == ("-sigalg", "SHA384withRSA")
        return self.request.csr_pem

    def import_certificate_reply(self, plan, *, expected_before):
        assert self.locked
        assert expected_before == self.current
        assert isinstance(plan, CertificateImportPlan)
        self.events.append("import")
        if self.failure:
            raise self.failure
        self.current = self.after or PublicKeystoreState(
            metadata(2), plan.certificate_chain_der
        )
        return self.status


def test_deterministic_import_command_does_not_read_password(monkeypatch):
    monkeypatch.setenv("UNIFI_KEYSTORE_PASSWORD", "synthetic-do-not-disclose")
    assert build_keytool_importcert_command() == (
        "/usr/bin/keytool",
        "-importcert",
        "-alias",
        "unifi",
        "-keystore",
        "/config/data/keystore",
        "-storetype",
        "PKCS12",
        "-storepass:env",
        "UNIFI_KEYSTORE_PASSWORD",
        "-keypass:env",
        "UNIFI_KEYSTORE_PASSWORD",
        "-noprompt",
    )


@pytest.mark.parametrize("field", ["alias", "keystore_path", "password_env_name"])
@pytest.mark.parametrize(
    "value",
    [
        "",
        None,
        "-delete",
        "../keystore",
        "/tmp/keystore",
        "unifi;echo unsafe",
        "unsafe\nvalue",
        "x" * 5000,
    ],
)
def test_import_target_is_fixed(field, value):
    with pytest.raises(UnifiOperationError):
        build_keytool_importcert_command(**{field: value})


def test_prepares_exact_public_reply_and_verifies_import(installation_material):
    request = installation_material.request
    plan = prepare_certificate_import(request)
    certificates = x509.load_pem_x509_certificates(plan.reply_pem)
    assert len(certificates) == 2
    assert (
        tuple(public_der(cert) for cert in certificates) == plan.certificate_chain_der
    )
    assert plan.reply_pem == request.issued_certificate + request.trusted_ca_data
    boundary = FakeBoundary(request)
    installed = UnifiClient(boundary).install_certificate(request)
    assert installed.certificate == plan.issued
    assert installed.alias.entry_type == "PrivateKeyEntry"
    assert installed.alias.certificate_chain_length == 2
    assert boundary.events == ["lock", "inspect", "import", "inspect", "unlock"]


@pytest.mark.parametrize(
    "data", [b"", b"invalid", "not bytes", b"x" * (MAX_ISSUED_CERTIFICATE_BYTES + 1)]
)
def test_invalid_leaf_never_reaches_import(installation_material, data):
    request = replace(installation_material.request, issued_certificate=data)
    boundary = FakeBoundary(request)
    with pytest.raises(UnifiOperationError, match="pre-import"):
        UnifiClient(boundary).install_certificate(request)
    assert "import" not in boundary.events


def test_rejects_pem_smuggling_and_multiple_leaves(installation_material):
    request = installation_material.request
    for data in (
        request.issued_certificate * 2,
        request.issued_certificate + b"-----BEGIN PRIVATE KEY-----\ninvalid\n",
        b"prefix" + request.issued_certificate,
    ):
        with pytest.raises(ValueError):
            prepare_certificate_import(replace(request, issued_certificate=data))


@pytest.mark.parametrize(
    "change",
    ["spki", "subject", "san", "ca-leaf", "issuer", "expired", "future", "lifetime"],
)
def test_issued_policy_failures_block_import(installation_material, change):
    m = installation_material
    options = {
        "spki": {"key": m.ca_key},
        "subject": {"subject": "other.test"},
        "san": {"sans": [x509.DNSName("unexpected.test")]},
        "ca-leaf": {"ca": True},
        "issuer": {"signing_key": m.key},
        "expired": {
            "not_before": m.now - timedelta(days=31),
            "not_after": m.now - timedelta(days=1),
        },
        "future": {"not_before": m.now + timedelta(days=1)},
        "lifetime": {"not_after": m.now + timedelta(days=90)},
    }
    request = replace(
        m.request, issued_certificate=public_pem(m.issue(**options[change]))
    )
    boundary = FakeBoundary(request)
    with pytest.raises(UnifiOperationError, match="pre-import"):
        UnifiClient(boundary).install_certificate(request)
    assert "import" not in boundary.events


@pytest.mark.parametrize(
    "change",
    [
        "wrong-alias",
        "missing-alias",
        "trusted-entry",
        "type",
        "provider",
        "chain-length",
        "empty-chain",
        "huge-output",
        "other-key",
    ],
)
def test_preimport_state_preconditions(installation_material, change):
    request = installation_material.request
    before = request.before
    changes = {
        "wrong-alias": replace(
            before, keytool_output=metadata().replace("unifi", "other")
        ),
        "missing-alias": replace(before, keytool_output="Keystore type: PKCS12"),
        "trusted-entry": replace(
            before,
            keytool_output=metadata().replace("PrivateKeyEntry", "trustedCertEntry"),
        ),
        "type": replace(before, keytool_output=metadata().replace("PKCS12", "JKS")),
        "provider": replace(before, keytool_output=metadata().replace("SUN", "other")),
        "chain-length": replace(before, keytool_output=metadata(2)),
        "empty-chain": replace(before, certificate_chain_der=()),
        "huge-output": replace(
            before, keytool_output="x" * (MAX_KEYTOOL_OUTPUT_CHARS + 1)
        ),
        "other-key": replace(
            before, certificate_chain_der=(public_der(installation_material.ca),)
        ),
    }
    request = replace(request, before=changes[change])
    boundary = FakeBoundary(request)
    with pytest.raises(UnifiOperationError, match="pre-import"):
        UnifiClient(boundary).install_certificate(request)
    assert "import" not in boundary.events


@pytest.mark.parametrize(
    "change", ["baseline", "subject", "san", "bad-signature", "other-key"]
)
def test_csr_and_config_cannot_bypass_validation(installation_material, change):
    m = installation_material
    request = m.request
    if change == "baseline":
        request = replace(
            request, policy=replace(request.policy, expected_spki_sha256="0" * 64)
        )
    elif change in ("subject", "san", "other-key"):
        options = {
            "subject": {"subject": "other.test"},
            "san": {"sans": [x509.DNSName("other.test")]},
            "other-key": {"key": m.ca_key},
        }
        request = replace(request, csr_pem=m.make_csr(**options[change]))
    else:
        csr = x509.load_pem_x509_csr(request.csr_pem)
        corrupted = bytearray(public_der(csr))
        corrupted[-1] ^= 1
        request = replace(
            request,
            csr_pem=b"-----BEGIN CERTIFICATE REQUEST-----\n"
            + base64.b64encode(corrupted)
            + b"\n-----END CERTIFICATE REQUEST-----\n",
        )
    boundary = FakeBoundary(request)
    with pytest.raises(UnifiOperationError, match="pre-import"):
        UnifiClient(boundary).install_certificate(request)
    assert "import" not in boundary.events


@pytest.mark.parametrize(
    "change", ["empty", "malformed", "multiple", "oversized", "leaf"]
)
def test_ca_reply_rejects_unsupported_trust(installation_material, change):
    request = installation_material.request
    data = {
        "empty": b"",
        "malformed": b"garbage",
        "multiple": request.trusted_ca_data * 2,
        "oversized": b"x" * (MAX_TRUST_BUNDLE_BYTES + 1),
        "leaf": request.issued_certificate,
    }[change]
    boundary = FakeBoundary(request)
    with pytest.raises(UnifiOperationError, match="pre-import"):
        UnifiClient(boundary).install_certificate(
            replace(request, trusted_ca_data=data)
        )
    assert "import" not in boundary.events


def test_fresh_inspection_detects_concurrent_same_key_reissuance(installation_material):
    request = installation_material.request
    boundary = FakeBoundary(request)
    boundary.current = PublicKeystoreState(
        metadata(), (public_der(installation_material.issue()),)
    )
    with pytest.raises(UnifiOperationError, match="pre-import"):
        UnifiClient(boundary).install_certificate(request)
    assert boundary.events == ["lock", "inspect", "unlock"]


@pytest.mark.parametrize("status", [1, -9, True, None, "0"])
def test_import_failure_does_not_inspect_or_retry(installation_material, status):
    request = installation_material.request
    boundary = FakeBoundary(request)
    boundary.status = status
    with pytest.raises(UnifiOperationError, match="keystore may have changed"):
        UnifiClient(boundary).install_certificate(request)
    assert boundary.events == ["lock", "inspect", "import", "unlock"]


@pytest.mark.parametrize(
    "change",
    [
        "fingerprint",
        "spki",
        "entry",
        "alias",
        "chain-length",
        "chain-ca",
        "chain-order",
        "provider",
        "malformed",
    ],
)
def test_postimport_mismatch_is_failure(installation_material, change):
    m = installation_material
    request = m.request
    plan = prepare_certificate_import(request)
    good = PublicKeystoreState(metadata(2), plan.certificate_chain_der)
    changes = {
        "fingerprint": replace(
            good,
            certificate_chain_der=(
                public_der(m.issue()),
                plan.certificate_chain_der[1],
            ),
        ),
        "spki": replace(
            good,
            certificate_chain_der=(
                public_der(m.issue(key=m.ca_key)),
                plan.certificate_chain_der[1],
            ),
        ),
        "entry": replace(
            good,
            keytool_output=metadata(2).replace("PrivateKeyEntry", "trustedCertEntry"),
        ),
        "alias": replace(good, keytool_output=metadata(2).replace("unifi", "other")),
        "chain-length": replace(good, keytool_output=metadata()),
        "chain-ca": replace(
            good,
            certificate_chain_der=(
                plan.certificate_chain_der[0],
                plan.certificate_chain_der[0],
            ),
        ),
        "chain-order": replace(
            good, certificate_chain_der=tuple(reversed(plan.certificate_chain_der))
        ),
        "provider": replace(good, keytool_output=metadata(2).replace("SUN", "other")),
        "malformed": replace(
            good, certificate_chain_der=(b"invalid", plan.certificate_chain_der[1])
        ),
    }
    boundary = FakeBoundary(request)
    boundary.after = changes[change]
    with pytest.raises(UnifiOperationError, match="post-import verification"):
        UnifiClient(boundary).install_certificate(request)
    assert boundary.events == ["lock", "inspect", "import", "inspect", "unlock"]


@pytest.mark.parametrize("operation", ["inspect", "csr", "import"])
def test_execution_diagnostics_are_not_exposed(
    installation_material, operation, capsys
):
    request = installation_material.request
    boundary = FakeBoundary(request)
    failure = RuntimeError("synthetic-password\n\x1b[31mcredential detail")
    client = UnifiClient(boundary)
    if operation == "inspect":
        boundary.inspect_public_state = Mock(side_effect=failure)
        call = partial(client.inspect_current, request.policy)
    elif operation == "csr":
        boundary.generate_csr = Mock(side_effect=failure)
        call = partial(client.request_csr, request.policy)
    else:
        boundary.failure = failure
        call = partial(client.install_certificate, request)
    with pytest.raises(UnifiOperationError) as raised:
        call()
    output = "".join(traceback.format_exception(raised.value))
    assert "synthetic-password" not in output
    assert "credential detail" not in output
    assert capsys.readouterr() == ("", "")


def test_arbitrary_plan_or_bytes_cannot_be_installed(installation_material):
    request = installation_material.request
    boundary = FakeBoundary(request)
    for value in (request.issued_certificate, prepare_certificate_import(request)):
        with pytest.raises(UnifiOperationError, match="pre-import"):
            UnifiClient(boundary).install_certificate(value)
    assert "import" not in boundary.events


def test_verification_revalidates_expiry_instead_of_trusting_plan(
    installation_material,
):
    request = installation_material.request
    plan = prepare_certificate_import(request)
    with pytest.raises(ValueError, match="expired"):
        verify_certificate_import(
            PublicKeystoreState(metadata(2), plan.certificate_chain_der),
            request,
            now=installation_material.now + timedelta(days=31),
        )


@pytest.mark.parametrize(
    "change", ["intermediate", "bad-self-signature", "expired", "future"]
)
def test_installation_requires_current_self_signed_ca(installation_material, change):
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import NameOID

    m = installation_material
    ca = m.ca
    issuer = (
        ca.subject
        if change != "intermediate"
        else x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Parent CA")])
    )
    builder = (
        x509.CertificateBuilder()
        .subject_name(ca.subject)
        .issuer_name(issuer)
        .public_key(m.ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(
            m.now + timedelta(days=1)
            if change == "future"
            else m.now - timedelta(days=40)
        )
        .not_valid_after(
            m.now - timedelta(days=1)
            if change == "expired"
            else m.now + timedelta(days=365)
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
    )
    invalid_ca = builder.sign(
        m.key if change == "bad-self-signature" else m.ca_key, hashes.SHA256()
    )
    request = replace(m.request, trusted_ca_data=public_pem(invalid_ca))
    boundary = FakeBoundary(request)
    with pytest.raises(UnifiOperationError, match="pre-import"):
        UnifiClient(boundary).install_certificate(request)
    assert "import" not in boundary.events


def test_der_inputs_are_canonicalized_to_the_same_public_reply(installation_material):
    request = installation_material.request
    plan = prepare_certificate_import(request)
    der_request = replace(
        request,
        issued_certificate=plan.certificate_chain_der[0],
        trusted_ca_data=plan.certificate_chain_der[1],
    )
    assert prepare_certificate_import(der_request) == plan


def test_lock_failure_never_dispatches_import(installation_material):
    request = installation_material.request
    boundary = FakeBoundary(request)
    boundary.exclusive = Mock(side_effect=RuntimeError("synthetic-secret"))
    with pytest.raises(UnifiOperationError, match="pre-import"):
        UnifiClient(boundary).install_certificate(request)
    assert boundary.events == []


def test_fresh_inspections_and_verification_share_one_exclusive_context(
    installation_material, monkeypatch
):
    import unifi_client

    request = installation_material.request
    boundary = FakeBoundary(request)
    inspect = boundary.inspect_public_state
    verify = unifi_client.verify_certificate_import
    guarded_calls = []

    def guarded_inspect():
        assert boundary.locked
        guarded_calls.append("inspect")
        return inspect()

    def guarded_verify(*args, **kwargs):
        assert boundary.locked
        guarded_calls.append("verify")
        return verify(*args, **kwargs)

    boundary.inspect_public_state = guarded_inspect
    monkeypatch.setattr(unifi_client, "verify_certificate_import", guarded_verify)
    UnifiClient(boundary).install_certificate(request)
    assert guarded_calls == ["inspect", "inspect", "verify"]
    assert boundary.events == ["lock", "inspect", "import", "inspect", "unlock"]
    assert boundary.locked is False


def test_different_rsa_4096_reply_is_rejected_before_keytool(installation_material):
    from cryptography.hazmat.primitives.asymmetric import rsa

    # The live Java rejection is defence in depth, not our precondition check.
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    request = replace(
        installation_material.request,
        issued_certificate=public_pem(installation_material.issue(key=other_key)),
    )
    boundary = FakeBoundary(request)
    with pytest.raises(UnifiOperationError, match="pre-import"):
        UnifiClient(boundary).install_certificate(request)
    assert boundary.events == ["lock", "unlock"]
