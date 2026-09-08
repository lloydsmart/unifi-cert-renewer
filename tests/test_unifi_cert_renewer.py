import traceback
from dataclasses import replace
from unittest.mock import Mock

import pytest
from conftest import public_pem
from cryptography import x509
from test_certificate_installation import FakeBoundary

from opnsense_client import CA_LIST_PATH, CERT_ADD_PATH, OPNsenseClient
from unifi_cert_renewer import RenewalStageError, run_to_installation
from unifi_client import UnifiClient

CA_REF = "0123456789abc"
CERT_UUID = "abcdef12-1234-5678-9234-567812345678"


@pytest.fixture
def workflow(installation_material):
    request = installation_material.request
    boundary = FakeBoundary(request)
    opnsense = Mock(spec=OPNsenseClient)
    opnsense.resolve_ca.side_effect = lambda description: (
        boundary.events.append("resolve") or CA_REF
    )
    opnsense.sign_csr.side_effect = lambda *args, **kwargs: (
        boundary.events.append("sign") or CERT_UUID
    )
    opnsense.get_certificate.side_effect = lambda uuid: (
        boundary.events.append("retrieve") or request.issued_certificate
    )
    arguments = dict(
        unifi=UnifiClient(boundary),
        opnsense=opnsense,
        policy=request.policy,
        trusted_ca_data=request.trusted_ca_data,
        ca_description="Test root",
        certificate_description="UniFi HTTPS",
        lifetime_days=30,
    )
    return boundary, opnsense, arguments


def test_default_prepares_without_importing(workflow):
    boundary, opnsense, arguments = workflow
    result = run_to_installation(**arguments)
    assert boundary.events == ["inspect", "csr", "resolve", "sign", "retrieve"]
    assert result.state == "prepared"
    assert result.installed is None
    assert result.renewal_complete is False
    assert result.request.before == boundary.request.before
    assert (
        opnsense.sign_csr.call_args.kwargs["expected_spki_sha256"]
        == arguments["policy"].expected_spki_sha256
    )
    assert opnsense.sign_csr.call_args.kwargs["caref"] == CA_REF
    opnsense.get_certificate.assert_called_once_with(CERT_UUID)


def test_explicit_install_returns_pending_live_verification(workflow):
    boundary, _, arguments = workflow
    result = run_to_installation(**arguments, install=True)
    assert boundary.events == [
        "inspect",
        "csr",
        "resolve",
        "sign",
        "retrieve",
        "lock",
        "inspect",
        "import",
        "inspect",
        "unlock",
    ]
    assert result.state == "installed_pending_live_verification"
    assert result.installed.certificate == result.plan.issued
    assert result.renewal_complete is False


@pytest.mark.parametrize(
    "failure_stage",
    [
        "inspect",
        "csr",
        "resolve",
        "sign",
        "retrieve",
        "validate",
        "import",
        "post-import",
    ],
)
def test_failures_stop_the_sequence_without_leaking_or_retrying(
    workflow, failure_stage
):
    boundary, opnsense, arguments = workflow
    failure = RuntimeError("synthetic-api-secret\n\x1b[31munsafe")
    if failure_stage in {"inspect", "csr"}:
        name = "inspect_public_state" if failure_stage == "inspect" else "generate_csr"
        setattr(boundary, name, Mock(side_effect=failure))
    elif failure_stage in {"resolve", "sign", "retrieve"}:
        name = {
            "resolve": "resolve_ca",
            "sign": "sign_csr",
            "retrieve": "get_certificate",
        }[failure_stage]
        getattr(opnsense, name).side_effect = failure
    elif failure_stage == "validate":
        opnsense.get_certificate.side_effect = None
        opnsense.get_certificate.return_value = b"invalid"
    elif failure_stage == "import":
        boundary.failure = failure
    else:
        boundary.after = boundary.request.before
    with pytest.raises(RenewalStageError) as raised:
        run_to_installation(**arguments, install=True)
    rendered = "".join(traceback.format_exception(raised.value))
    assert "synthetic-api-secret" not in rendered
    assert boundary.events.count("import") <= 1
    assert opnsense.sign_csr.call_count <= 1
    if failure_stage not in {"import", "post-import"}:
        assert "import" not in boundary.events
    if failure_stage in {"inspect", "csr", "resolve"}:
        opnsense.sign_csr.assert_not_called()
    if failure_stage in {"inspect", "csr", "resolve", "sign"}:
        opnsense.get_certificate.assert_not_called()


@pytest.mark.parametrize("change", ["subject", "sans", "key", "invalid"])
def test_wrong_generated_csr_is_never_sent_to_ca(
    workflow, installation_material, change
):
    boundary, opnsense, arguments = workflow
    csr = {
        "subject": installation_material.make_csr(subject="other.test"),
        "sans": installation_material.make_csr(sans=[x509.DNSName("other.test")]),
        "key": installation_material.make_csr(key=installation_material.ca_key),
        "invalid": b"invalid",
    }[change]
    boundary.request = replace(boundary.request, csr_pem=csr)
    with pytest.raises(RenewalStageError, match="CSR"):
        run_to_installation(**arguments)
    opnsense.resolve_ca.assert_not_called()
    opnsense.sign_csr.assert_not_called()


@pytest.mark.parametrize(
    "overrides",
    [
        {"trusted_ca_data": b"invalid"},
        {"lifetime_days": True},
        {"lifetime_days": 0},
        {"lifetime_days": 398},
        {"digest": "sha1"},
        {"install": "true"},
    ],
)
def test_invalid_config_prevents_device_operations(workflow, overrides):
    boundary, opnsense, arguments = workflow
    arguments.update(overrides)
    with pytest.raises(RenewalStageError, match="configuration"):
        run_to_installation(**arguments)
    assert boundary.events == []
    opnsense.resolve_ca.assert_not_called()


def test_real_opnsense_methods_are_composed_with_only_narrow_api_routes(workflow):
    boundary, _, arguments = workflow
    # Bypass only constructor IO; exercise actual resolve/sign/retrieve methods.
    client = object.__new__(OPNsenseClient)
    calls = []

    def response(method, path, payload=None):
        calls.append((method, path, payload))
        if path == CA_LIST_PATH:
            return {"rows": [{"descr": "Test root", "caref": CA_REF}], "count": 1}
        if path == CERT_ADD_PATH:
            assert payload["cert"]["csr_payload"].encode() == boundary.request.csr_pem
            assert payload["cert"]["key_type"] == "2048"
            assert payload["cert"]["altnames_dns"] == "unifi.test"
            return {"result": "saved", "uuid": CERT_UUID}
        assert path.endswith(f"/{CERT_UUID}/crt")
        assert payload == {}
        return {"status": "ok", "payload": boundary.request.issued_certificate.decode()}

    client._request_json = response
    arguments["opnsense"] = client
    result = run_to_installation(**arguments)
    assert result.state == "prepared"
    assert len(calls) == 3


def test_certificate_from_different_signing_ca_is_rejected(
    workflow, installation_material
):
    boundary, opnsense, arguments = workflow
    opnsense.get_certificate.side_effect = None
    opnsense.get_certificate.return_value = public_pem(
        installation_material.issue(signing_key=installation_material.key)
    )
    with pytest.raises(RenewalStageError, match="issued certificate"):
        run_to_installation(**arguments, install=True)
    assert "import" not in boundary.events


def test_current_key_mismatch_stops_before_csr_or_signing(workflow):
    boundary, opnsense, arguments = workflow
    arguments["policy"] = replace(arguments["policy"], expected_spki_sha256="0" * 64)
    with pytest.raises(RenewalStageError, match="current UniFi inspection"):
        run_to_installation(**arguments)
    assert boundary.events == ["inspect"]
    opnsense.resolve_ca.assert_not_called()
    opnsense.sign_csr.assert_not_called()


@pytest.mark.parametrize(
    "failure_type", [TimeoutError, InterruptedError, KeyboardInterrupt]
)
@pytest.mark.parametrize("failure_point", ["import", "post-inspection", "context-exit"])
def test_interrupted_or_ambiguous_import_never_returns_a_result(
    workflow, failure_type, failure_point
):
    from contextlib import contextmanager

    boundary, _, arguments = workflow
    import_reply = boundary.import_certificate_reply
    inspect = boundary.inspect_public_state
    exclusive = boundary.exclusive

    def fail_after_mutation(*args, **kwargs):
        status = import_reply(*args, **kwargs)
        if failure_point == "import":
            raise failure_type("synthetic-sensitive-diagnostic")
        return status

    def fail_post_inspection():
        state = inspect()
        if failure_point == "post-inspection" and "import" in boundary.events:
            raise failure_type("synthetic-sensitive-diagnostic")
        return state

    @contextmanager
    def fail_context_exit():
        with exclusive():
            yield
            if failure_point == "context-exit":
                raise failure_type("synthetic-sensitive-diagnostic")

    boundary.import_certificate_reply = fail_after_mutation
    boundary.inspect_public_state = fail_post_inspection
    boundary.exclusive = fail_context_exit
    results = []
    expected_error = (
        KeyboardInterrupt if failure_type is KeyboardInterrupt else RenewalStageError
    )
    with pytest.raises(expected_error):
        results.append(run_to_installation(**arguments, install=True))
    assert results == []
    assert boundary.current != boundary.request.before  # Mutation happened.
    assert boundary.events.count("import") == 1  # No automatic retry.
    assert boundary.events[-1] == "unlock"
    assert boundary.locked is False

    # Recovery starts from a new public read, even after context-exit failure.
    # This mock has no child process; production must first prove it terminated.
    boundary.inspect_public_state = inspect
    before_recovery = len(boundary.events)
    recovered = arguments["unifi"].inspect_current(arguments["policy"])
    assert len(boundary.events) == before_recovery + 1
    assert boundary.events[-1] == "inspect"
    assert recovered == boundary.current
    assert results == []  # A fresh keystore read cannot establish live TLS success.
