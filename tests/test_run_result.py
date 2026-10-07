"""Schema-v1 adapter and worker-visible evidence tests."""

import json
import re
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from conftest import policy_for
from test_certificate_installation import FakeBoundary
from test_production_renewer import parsed_config, public_state_expiring_at

import production_renewer as worker
from run_result import Change, Milestone, Outcome, Reason, RunEvidence, Stage
from unifi_client import UnifiClient

TOP = {
    "schema_version",
    "product",
    "operation",
    "attempt_id",
    "started_at",
    "finished_at",
    "outcome",
    "stage",
    "manual_recovery_required",
    "reason_code",
    "message",
    "results",
}
TARGET = {
    "target",
    "outcome",
    "stage",
    "renewal_due",
    "change",
    "manual_recovery_required",
    "reason_code",
    "message",
    "certificate",
    "milestones",
}
MILESTONES = {"csr", "issuance", "installation", "activation", "live_tls"}
OPERATIONS = {
    "inspect",
    "renew_due",
    "renew_now",
    "generate_csr",
    "retrieve_csr",
    "sign_csr",
    "install",
}


def shared(capsys, *args):
    code = worker.main(list(args))
    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out.endswith("\n") and not captured.out.endswith("\n\n")
    result = json.loads(captured.out)
    assert captured.out == json.dumps(result, ensure_ascii=True, allow_nan=False) + "\n"
    assert set(result) == TOP
    assert result["schema_version"] == 1 and type(result["schema_version"]) is int
    assert result["product"] == "unifi"
    assert result["operation"] in OPERATIONS
    attempt = UUID(result["attempt_id"])
    assert attempt.version == 4 and str(attempt) == result["attempt_id"]
    for name in ("started_at", "finished_at"):
        assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", result[name])
        assert datetime.fromisoformat(result[name].replace("Z", "+00:00")).tzinfo == UTC
    assert len(result["results"]) == 1
    target = result["results"][0]
    assert set(target) == TARGET
    assert target["target"] == "unifi"
    assert set(target["milestones"]) == MILESTONES
    assert set(target["milestones"].values()) <= {item.value for item in Milestone}
    assert target["outcome"] in {item.value for item in Outcome}
    assert target["stage"] in {item.value for item in Stage}
    assert target["change"] in {item.value for item in Change}
    assert target["reason_code"] is None or target["reason_code"] in {
        item.value for item in Reason
    }
    assert target["renewal_due"] is None or type(target["renewal_due"]) is bool
    assert type(target["manual_recovery_required"]) is bool
    assert result["manual_recovery_required"] == target["manual_recovery_required"]
    if target["certificate"] is not None:
        assert set(target["certificate"]) == {"fingerprint_sha256", "expiry_date"}
        assert re.fullmatch(
            r"[0-9a-f]{64}", target["certificate"]["fingerprint_sha256"]
        )
        assert re.fullmatch(r"\d{4}-\d\d-\d\d", target["certificate"]["expiry_date"])
    return code, result, target


@pytest.mark.parametrize(
    "args",
    [
        ("inspect", "--output", "json"),
        ("--output", "json", "inspect"),
        ("--output=json", "inspect"),
    ],
)
def test_parser_order_and_config_failure(args, monkeypatch, capsys):
    def fail():
        raise ValueError("SECRET_CONFIG_PATH")

    monkeypatch.setattr(worker, "load_production_config", fail)
    code, result, target = shared(capsys, *args)
    assert code == 1
    assert result["operation"] == "inspect"
    assert (target["outcome"], target["stage"], target["reason_code"]) == (
        "failure_pre_attempt",
        "configuration",
        "config_invalid",
    )
    assert "SECRET_CONFIG_PATH" not in json.dumps(result)


@pytest.mark.parametrize(
    "args", [[], ["unknown"], ["inspect", "csr"], ["--output", "xml", "inspect"]]
)
def test_parse_errors_have_legacy_usage_only(args, capsys):
    assert worker.main(args) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert (
        captured.err
        == "Usage: production_renewer.py {inspect|csr|prepare|install|renew}\n"
    )


@pytest.mark.parametrize(
    "offset,expected",
    [
        (timedelta(days=31), False),
        (timedelta(days=30), True),
        (timedelta(days=-1), True),
    ],
)
def test_shared_inspect_threshold(
    installation_material, monkeypatch, capsys, offset, expected
):
    config = parsed_config(installation_material)
    now = installation_material.now
    boundary = FakeBoundary(installation_material.request)
    boundary.current = public_state_expiring_at(installation_material, now + offset)
    monkeypatch.setattr(worker, "load_production_config", lambda: config)
    monkeypatch.setattr(
        worker,
        "build_production_unifi_client",
        lambda authority, **kw: UnifiClient(boundary),
    )
    monkeypatch.setattr(
        worker, "OPNsenseClient", lambda *a, **kw: pytest.fail("signer called")
    )
    monkeypatch.setattr(
        worker, "run_to_installation", lambda **kw: pytest.fail("mutation called")
    )
    monkeypatch.setattr(
        worker,
        "_renewal_is_due",
        lambda cert, days, now=None: (
            cert.not_valid_after <= installation_material.now + timedelta(days=days)
        ),
    )
    code, result, target = shared(capsys, "inspect", "--output=json")
    assert code == 0
    assert target["outcome"] == ("attention_due" if expected else "success_no_change")
    message = (
        "Certificate renewal attention is due."
        if expected
        else "Certificate is outside the renewal window."
    )
    assert target["message"] == result["message"] == message
    assert target["stage"] == ("decision" if expected else "completed")
    assert target["renewal_due"] is expected
    assert target["change"] == "none"
    assert set(target["milestones"].values()) == {"not_attempted"}
    assert boundary.events == ["inspect"]


def test_csr_and_legacy_output(installation_material, monkeypatch, capsys):
    config = parsed_config(installation_material)
    boundary = FakeBoundary(installation_material.request)
    monkeypatch.setattr(worker, "load_production_config", lambda: config)
    monkeypatch.setattr(
        worker,
        "build_production_unifi_client",
        lambda authority, **kw: UnifiClient(boundary),
    )
    code, result, target = shared(capsys, "csr", "--output", "json")
    assert code == 0 and result["operation"] == "generate_csr"
    assert (target["outcome"], target["change"], target["certificate"]) == (
        "success_prepared",
        "none",
        None,
    )
    assert target["milestones"]["csr"] == "confirmed"
    assert set(v for k, v in target["milestones"].items() if k != "csr") == {
        "not_attempted"
    }
    assert worker.main(["csr"]) == 0
    legacy = capsys.readouterr()
    expected = {
        "mode": "csr",
        "csr": worker._csr_output(
            worker.validate_requested_csr(
                installation_material.request.csr_pem, config.policy
            )
        ),
    }
    assert (
        legacy.out == json.dumps(expected, sort_keys=True, separators=(",", ":")) + "\n"
    )


def test_signing_evidence_and_prepare_never_installs(
    installation_material, monkeypatch, capsys
):
    config = replace(
        parsed_config(installation_material),
        authority=policy_for(installation_material),
    )
    boundary = FakeBoundary(installation_material.request)
    calls = []

    class Signer:
        def resolve_ca(self, description):
            return "0123456789abc"

        def sign_csr(self, *args, before_transport, **kwargs):
            calls.append("sign")
            before_transport()
            return "abcdef12-1234-5678-9234-567812345678"

        def get_certificate(self, uuid):
            return installation_material.request.issued_certificate

    monkeypatch.setattr(worker, "load_production_config", lambda: config)
    monkeypatch.setattr(
        worker,
        "build_production_unifi_client",
        lambda authority, **kw: UnifiClient(boundary),
    )
    monkeypatch.setattr(worker, "OPNsenseClient", lambda *a, **kw: Signer())
    monkeypatch.setattr(
        worker, "_lifecycle_lock", lambda: __import__("contextlib").nullcontext()
    )
    code, result, target = shared(capsys, "prepare", "--output=json")
    assert code == 0 and result["operation"] == "sign_csr", target
    assert (target["outcome"], target["change"]) == ("success_prepared", "confirmed")
    assert (
        target["milestones"]["csr"] == target["milestones"]["issuance"] == "confirmed"
    )
    assert target["milestones"]["installation"] == "not_attempted"
    assert set(target["certificate"]) == {"fingerprint_sha256", "expiry_date"}
    assert calls == ["sign"] and "import" not in boundary.events


@pytest.mark.parametrize(
    "phase,outcome,change,issuance,recovery",
    [
        ("before", "failure_pre_attempt", "none", "not_attempted", False),
        ("dispatch", "failure_ambiguous", "possible", "uncertain", True),
        ("saved", "failure_partial", "confirmed", "confirmed", True),
    ],
)
def test_signing_failure_boundaries(
    installation_material,
    monkeypatch,
    capsys,
    phase,
    outcome,
    change,
    issuance,
    recovery,
):
    config = replace(
        parsed_config(installation_material),
        authority=policy_for(installation_material),
    )
    boundary = FakeBoundary(installation_material.request)

    class Signer:
        def resolve_ca(self, description):
            return "0123456789abc"

        def sign_csr(self, *args, before_transport, **kwargs):
            if phase == "before":
                raise ValueError("SECRET_BEFORE")
            before_transport()
            if phase == "dispatch":
                raise ValueError("SECRET_HTTP")
            return "abcdef12-1234-5678-9234-567812345678"

        def get_certificate(self, uuid):
            raise ValueError("SECRET_RESPONSE")

    monkeypatch.setattr(worker, "load_production_config", lambda: config)
    monkeypatch.setattr(
        worker,
        "build_production_unifi_client",
        lambda authority, **kw: UnifiClient(boundary),
    )
    monkeypatch.setattr(worker, "OPNsenseClient", lambda *a, **kw: Signer())
    monkeypatch.setattr(
        worker, "_lifecycle_lock", lambda: __import__("contextlib").nullcontext()
    )
    code, _, target = shared(capsys, "prepare", "--output=json")
    assert code == 1
    assert (
        target["outcome"],
        target["change"],
        target["milestones"]["issuance"],
        target["manual_recovery_required"],
    ) == (outcome, change, issuance, recovery)
    assert "SECRET_" not in json.dumps(target)
    assert "import" not in boundary.events


def test_run_evidence_install_and_verify_boundaries():
    evidence = RunEvidence("install")
    evidence.stage = "installation"
    evidence.confirm("issuance")
    evidence.executor_dispatch("install")
    evidence.failure()
    assert evidence.target.outcome is Outcome.FAILURE_AMBIGUOUS
    assert evidence.target.milestones["installation"] is Milestone.UNCERTAIN
    evidence.confirm("installation")
    evidence.stage = "live_verification"
    evidence.failure()
    assert evidence.target.outcome is Outcome.FAILURE_PARTIAL
    evidence.executor_dispatch("verify_pending")
    evidence.failure()
    assert evidence.target.outcome is Outcome.FAILURE_AMBIGUOUS
    assert evidence.target.milestones["activation"] is Milestone.UNCERTAIN
    assert evidence.target.milestones["live_tls"] is Milestone.UNCERTAIN


def test_busy_shared_and_legacy(installation_material, monkeypatch, capsys):
    from contextlib import contextmanager

    @contextmanager
    def busy():
        raise worker._LifecycleBusy
        yield

    monkeypatch.setattr(worker, "_lifecycle_lock", busy)
    monkeypatch.setattr(
        worker, "load_production_config", lambda: pytest.fail("config called")
    )
    code, _, target = shared(capsys, "renew", "--output=json")
    assert code == 75
    assert (
        target["outcome"],
        target["stage"],
        target["reason_code"],
        target["change"],
    ) == ("failure_pre_attempt", "lock", "lock_busy", "none")
    assert target["manual_recovery_required"] is False
    assert worker.main(["renew"]) == 75
    assert (
        capsys.readouterr().out
        == '{"mode":"renew","renewal_complete":false,"state":"busy"}\n'
    )


def test_closed_schema_vocabularies():
    from run_result import Operation

    assert {item.value for item in Operation} == OPERATIONS
    assert {item.value for item in Outcome} == {
        "success_changed",
        "success_no_change",
        "success_prepared",
        "attention_due",
        "failure_pre_attempt",
        "failure_partial",
        "failure_ambiguous",
    }
    assert {item.value for item in Stage} == {
        "startup",
        "configuration",
        "lock",
        "inspection",
        "decision",
        "preflight",
        "csr_generation",
        "csr_retrieval",
        "signing",
        "issued_validation",
        "installation",
        "activation",
        "live_verification",
        "finalization",
        "completed",
    }
    assert {item.value for item in Reason} == {
        "config_invalid",
        "lock_busy",
        "lock_failed",
        "pending_state",
        "inspection_failed",
        "csr_failed",
        "signing_failed",
        "validation_failed",
        "installation_failed",
        "verification_failed",
        "recovery_required",
        "unexpected_failure",
    }


def test_executor_socket_write_evidence_boundary(monkeypatch, installation_material):
    import os
    import stat
    from types import SimpleNamespace

    import unifi_executor_client as protocol
    from unifi_client import UnifiOperationError

    events = []
    phase = {"value": "connect"}
    directory = SimpleNamespace(
        st_mode=stat.S_IFDIR | 0o750, st_uid=0, st_gid=os.getgid()
    )
    endpoint = SimpleNamespace(
        st_mode=stat.S_IFSOCK | 0o660, st_uid=0, st_gid=os.getgid(), st_dev=1, st_ino=2
    )

    class Connection:
        def settimeout(self, timeout):
            pass

        def connect(self, path):
            events.append("connect")
            if phase["value"] == "connect":
                raise OSError("SECRET_SOCKET")

        def sendall(self, data):
            events.append("send")
            if phase["value"] == "send":
                raise OSError("SECRET_SEND")

        def recv(self, length):
            raise OSError("SECRET_LOST_RESPONSE")

        def close(self):
            pass

    monkeypatch.setattr(
        protocol,
        "socket",
        SimpleNamespace(AF_UNIX=1, SOCK_STREAM=1, socket=lambda *a: Connection()),
    )
    monkeypatch.setattr(
        protocol,
        "os",
        SimpleNamespace(
            stat=lambda path, **kw: (
                directory if path == protocol.SOCKET_DIRECTORY else endpoint
            )
        ),
    )
    boundary = protocol.SocketUnifiExecutionBoundary(
        policy_for(installation_material),
        on_dispatch=lambda operation: events.append(operation),
    )
    for test_phase, expected in (
        ("connect", ["connect"]),
        ("send", ["connect", "install", "send"]),
        ("response", ["connect", "install", "send"]),
    ):
        phase["value"] = test_phase
        events.clear()
        with pytest.raises(UnifiOperationError, match="request failed"):
            boundary._call("install", {})
        assert events == expected

    # Encoding and size checks occur after connection but before any request bytes.
    events.clear()
    with pytest.raises(UnifiOperationError, match="request failed"):
        boundary._call("install", {"too_large": "x" * protocol.MAX_MESSAGE_BYTES})
    assert events == ["connect"]


def test_opnsense_dispatch_hook_follows_local_opener_setup(monkeypatch):
    from urllib.request import Request

    import opnsense_client as client

    events = []
    request = Request("https://opnsense.test/api/trust/cert/add", method="POST")

    def failed_setup(*handlers):
        events.append("setup")
        raise ValueError("SECRET_LOCAL_SETUP")

    monkeypatch.setattr(client, "build_opener", failed_setup)
    with pytest.raises(ValueError):
        client._open_url(
            request,
            timeout=1,
            ssl_context=object(),
            before_transport=lambda: events.append("dispatch"),
        )
    assert events == ["setup"]

    class Opener:
        def open(self, request, *, timeout):
            events.append("open")
            raise OSError("SECRET_TRANSPORT")

    monkeypatch.setattr(
        client, "build_opener", lambda *handlers: events.append("setup") or Opener()
    )
    events.clear()
    with pytest.raises(OSError):
        client._open_url(
            request,
            timeout=1,
            ssl_context=object(),
            before_transport=lambda: events.append("dispatch"),
        )
    assert events == ["setup", "dispatch", "open"]


@pytest.mark.parametrize(
    "mode,phase,expected_outcome,installation,activation,live_tls",
    [
        (
            "install",
            "success",
            "success_changed",
            "confirmed",
            "confirmed",
            "confirmed",
        ),
        (
            "install",
            "install_pre",
            "failure_partial",
            "not_attempted",
            "not_attempted",
            "not_attempted",
        ),
        (
            "install",
            "install_send",
            "failure_ambiguous",
            "uncertain",
            "not_attempted",
            "not_attempted",
        ),
        (
            "install",
            "verify_pre",
            "failure_partial",
            "confirmed",
            "not_attempted",
            "not_attempted",
        ),
        (
            "install",
            "verify_send",
            "failure_ambiguous",
            "confirmed",
            "uncertain",
            "uncertain",
        ),
        (
            "install",
            "verify_reject",
            "failure_ambiguous",
            "confirmed",
            "uncertain",
            "uncertain",
        ),
        ("renew", "success", "success_changed", "confirmed", "confirmed", "confirmed"),
    ],
)
def test_shared_install_and_due_renew_evidence(
    installation_material,
    monkeypatch,
    capsys,
    mode,
    phase,
    expected_outcome,
    installation,
    activation,
    live_tls,
):
    from contextlib import nullcontext

    config = replace(
        parsed_config(installation_material),
        authority=policy_for(installation_material),
        renew_before_days=15,
    )
    request = installation_material.request
    before = (
        public_state_expiring_at(
            installation_material, installation_material.now + timedelta(days=15)
        )
        if mode == "renew"
        else request.before
    )
    snapshots = []

    class Boundary(FakeBoundary):
        def __init__(self):
            super().__init__(replace(request, before=before))
            self.current = before
            self.on_dispatch = None

        def import_certificate_reply(self, request, *, expected_before):
            if phase == "install_pre":
                raise ValueError("SECRET_LOCAL_IMPORT")
            self.on_dispatch("install")
            if phase == "install_send":
                raise ValueError("SECRET_LOST_IMPORT")
            result = super().import_certificate_reply(
                request, expected_before=expected_before
            )
            snapshots.append(self.on_dispatch.__self__.target.milestones["activation"])
            return result

        def verify_pending(self):
            if phase == "verify_pre":
                raise ValueError("SECRET_LOCAL_VERIFY")
            self.on_dispatch("verify_pending")
            if phase == "verify_send":
                raise ValueError("SECRET_LOST_VERIFY")
            if phase == "verify_reject":
                return "SECRET_REJECTION"
            return super().verify_pending()

    boundary = Boundary()

    class Signer:
        def resolve_ca(self, description):
            return "0123456789abc"

        def sign_csr(self, *args, before_transport, **kwargs):
            before_transport()
            return "abcdef12-1234-5678-9234-567812345678"

        def get_certificate(self, uuid):
            return request.issued_certificate

    def build(authority, **kwargs):
        boundary.on_dispatch = kwargs["on_dispatch"]
        return UnifiClient(boundary)

    monkeypatch.setattr(worker, "load_production_config", lambda: config)
    monkeypatch.setattr(worker, "build_production_unifi_client", build)
    monkeypatch.setattr(worker, "OPNsenseClient", lambda *a, **kw: Signer())
    monkeypatch.setattr(worker, "_lifecycle_lock", nullcontext)
    # Freeze only the threshold decision to the disposable fixture's reference time.
    monkeypatch.setattr(
        worker,
        "_renewal_is_due",
        lambda certificate, days, now=None: (
            certificate.not_valid_after
            <= installation_material.now + timedelta(days=days)
        ),
    )
    code, result, target = shared(capsys, mode, "--output=json")
    assert result["operation"] == ("install" if mode == "install" else "renew_due")
    assert code == (0 if phase == "success" else 1)
    assert target["outcome"] == expected_outcome
    assert target["milestones"]["installation"] == installation
    assert target["milestones"]["activation"] == activation
    assert target["milestones"]["live_tls"] == live_tls
    assert target["milestones"]["csr"] == "confirmed"
    assert target["milestones"]["issuance"] == "confirmed"
    assert target["change"] == "confirmed"
    assert target["manual_recovery_required"] is (phase != "success")
    assert target["renewal_due"] is (True if mode == "renew" else None)
    assert "SECRET_" not in json.dumps(result)
    if snapshots:
        assert snapshots == [Milestone.NOT_ATTEMPTED]


def test_shared_renew_not_due_stops_before_signing(
    installation_material, monkeypatch, capsys
):
    from contextlib import nullcontext

    config = replace(
        parsed_config(installation_material),
        authority=policy_for(installation_material),
        renew_before_days=15,
    )
    boundary = FakeBoundary(installation_material.request)
    monkeypatch.setattr(worker, "load_production_config", lambda: config)
    monkeypatch.setattr(
        worker,
        "build_production_unifi_client",
        lambda authority, **kw: UnifiClient(boundary),
    )
    monkeypatch.setattr(worker, "_lifecycle_lock", nullcontext)
    monkeypatch.setattr(
        worker, "OPNsenseClient", lambda *a, **kw: pytest.fail("signer called")
    )
    code, result, target = shared(capsys, "renew", "--output=json")
    assert code == 0
    assert (target["outcome"], target["renewal_due"], target["change"]) == (
        "success_no_change",
        False,
        "none",
    )
    assert set(target["milestones"].values()) == {"not_attempted"}
    assert (
        target["message"] == result["message"] == "Certificate is not due for renewal."
    )
    assert boundary.events == ["inspect"]


@pytest.mark.parametrize(
    "case", ["inspect", "csr", "prepare", "install", "renew_due", "renew_not_due"]
)
def test_legacy_output_exact_fixtures(case, installation_material, monkeypatch, capsys):
    from contextlib import nullcontext

    from unifi_client import inspect_public_keystore_state, prepare_certificate_import

    config = replace(
        parsed_config(installation_material),
        authority=policy_for(installation_material),
        renew_before_days=15,
    )
    request = installation_material.request
    due = case == "renew_due"
    before = (
        public_state_expiring_at(
            installation_material, installation_material.now + timedelta(days=15)
        )
        if due
        else request.before
    )
    boundary = FakeBoundary(replace(request, before=before))
    boundary.current = before

    class Signer:
        def resolve_ca(self, description):
            return "0123456789abc"

        def sign_csr(self, *args, **kwargs):
            return "abcdef12-1234-5678-9234-567812345678"

        def get_certificate(self, uuid):
            return request.issued_certificate

    monkeypatch.setattr(worker, "load_production_config", lambda: config)
    monkeypatch.setattr(
        worker, "build_production_unifi_client", lambda authority: UnifiClient(boundary)
    )
    monkeypatch.setattr(worker, "OPNsenseClient", lambda *a, **kw: Signer())
    monkeypatch.setattr(worker, "_lifecycle_lock", nullcontext)
    monkeypatch.setattr(
        worker,
        "_renewal_is_due",
        lambda certificate, days, now=None: (
            certificate.not_valid_after
            <= installation_material.now + timedelta(days=days)
        ),
    )

    def certificate(info):
        return {
            "subject": info.subject,
            "issuer": info.issuer,
            "serial_number": info.serial_number,
            "not_valid_before": info.not_valid_before.isoformat(),
            "not_valid_after": info.not_valid_after.isoformat(),
            "certificate_sha256": info.certificate_sha256,
            "spki_sha256": info.spki_sha256,
            "dns_sans": list(info.dns_sans),
            "ip_sans": list(info.ip_sans),
        }

    if case == "inspect":
        expected = {
            "mode": "inspect",
            "certificate": certificate(
                inspect_public_keystore_state(before).certificate
            ),
        }
        mode = "inspect"
    elif case == "csr":
        info = worker.validate_requested_csr(request.csr_pem, config.policy)
        expected = {
            "mode": "csr",
            "csr": {
                "subject": info.subject,
                "spki_sha256": info.spki_sha256,
                "public_key_algorithm": info.public_key_algorithm,
                "public_key_size": info.public_key_size,
                "dns_sans": list(info.dns_sans),
                "ip_sans": list(info.ip_sans),
                "signature_valid": info.signature_valid,
            },
        }
        mode = "csr"
    elif case == "renew_not_due":
        expected = {
            "mode": "renew",
            "state": "renewal_not_due",
            "renewal_due": False,
            "renewal_complete": False,
            "renew_before_days": 15,
            "certificate": certificate(
                inspect_public_keystore_state(before).certificate
            ),
        }
        mode = "renew"
    else:
        info = prepare_certificate_import(request).issued
        mode = "renew" if due else case
        expected = {
            "mode": mode,
            "state": "prepared" if case == "prepare" else "renewal_complete",
            "renewal_complete": case != "prepare",
            "issued_certificate": certificate(info),
        }
        if due:
            expected.update(renewal_due=True, renew_before_days=15)

    assert worker.main([mode]) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    assert (
        captured.out
        == json.dumps(expected, sort_keys=True, separators=(",", ":")) + "\n"
    )


@pytest.mark.parametrize("kind", ["malformed", "wrong_key", "invalid_pop", "identity"])
def test_shared_csr_rejects_unvalidated_material(
    kind, installation_material, monkeypatch, capsys
):
    import base64

    from cryptography.hazmat.primitives.asymmetric import rsa

    request = installation_material.request
    if kind == "malformed":
        csr = b"not a CSR"
    elif kind == "wrong_key":
        other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        csr = installation_material.make_csr(key=other)
    elif kind == "identity":
        csr = installation_material.make_csr(subject="other.test")
    else:
        body = b"".join(request.csr_pem.splitlines()[1:-1])
        der = bytearray(base64.b64decode(body))
        der[-1] ^= 1
        encoded = base64.encodebytes(bytes(der))
        csr = (
            b"-----BEGIN CERTIFICATE REQUEST-----\n"
            + encoded
            + b"-----END CERTIFICATE REQUEST-----\n"
        )

    class Boundary(FakeBoundary):
        def generate_csr(self, policy):
            self.events.append("csr")
            return csr

    boundary = Boundary(request)
    monkeypatch.setattr(
        worker, "load_production_config", lambda: parsed_config(installation_material)
    )
    monkeypatch.setattr(
        worker,
        "build_production_unifi_client",
        lambda authority, **kw: UnifiClient(boundary),
    )
    monkeypatch.setattr(
        worker, "OPNsenseClient", lambda *a, **kw: pytest.fail("signer called")
    )
    code, _, target = shared(capsys, "csr", "--output=json")
    assert code == 1
    assert (target["outcome"], target["stage"], target["reason_code"]) == (
        "failure_pre_attempt",
        "csr_generation",
        "csr_failed",
    )
    assert target["milestones"]["csr"] == "failed"
    assert target["change"] == "none"
    assert boundary.events == ["csr"]


def test_executor_frame_completed_before_dispatch(monkeypatch, installation_material):
    import os
    import stat
    import struct
    from types import SimpleNamespace

    import unifi_executor_client as protocol
    from unifi_client import UnifiOperationError

    directory = SimpleNamespace(
        st_mode=stat.S_IFDIR | 0o750, st_uid=0, st_gid=os.getgid()
    )
    endpoint = SimpleNamespace(
        st_mode=stat.S_IFSOCK | 0o660, st_uid=0, st_gid=os.getgid(), st_dev=1, st_ino=2
    )
    reply_data = json.dumps(
        {"version": 2, "ok": True, "result": {"state": "accepted"}},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    reply_frame = struct.pack("!I", len(reply_data)) + reply_data
    phase = {"value": "pack"}
    evidence = {"value": RunEvidence("install")}
    events = []
    connections = []

    class Connection:
        def __init__(self):
            self.incoming = bytearray(reply_frame)
            connections.append(self)

        def settimeout(self, timeout):
            pass

        def connect(self, path):
            events.append("connect")

        def sendall(self, frame):
            events.append(("send", frame))
            if phase["value"] == "send":
                raise OSError("synthetic send failure")

        def recv(self, length):
            result = bytes(self.incoming[:length])
            del self.incoming[:length]
            return result

        def close(self):
            pass

    def dispatch(operation):
        assert operation == "install"
        events.append("dispatch")
        if phase["value"] == "callback":
            raise ValueError("synthetic callback failure")
        evidence["value"].executor_dispatch(operation)

    monkeypatch.setattr(
        protocol,
        "socket",
        SimpleNamespace(AF_UNIX=1, SOCK_STREAM=1, socket=lambda *a: Connection()),
    )
    monkeypatch.setattr(
        protocol,
        "os",
        SimpleNamespace(
            stat=lambda path, **kw: (
                directory if path == protocol.SOCKET_DIRECTORY else endpoint
            )
        ),
    )
    boundary = protocol.SocketUnifiExecutionBoundary(
        policy_for(installation_material), on_dispatch=dispatch
    )
    request_data = json.dumps(
        {"version": 2, "operation": "install", "arguments": {}},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    expected_frame = struct.pack("!I", len(request_data)) + request_data

    for kind in ("pack", "concat", "callback", "send", "success"):
        phase["value"] = kind
        evidence["value"] = RunEvidence("install")
        events.clear()
        count = len(connections)
        with monkeypatch.context() as local:
            if kind == "pack":

                def fail_pack(*args):
                    raise ValueError("synthetic framing failure")

                local.setattr(protocol, "struct", SimpleNamespace(pack=fail_pack))
            elif kind == "concat":

                class Prefix:
                    def __add__(self, other):
                        raise ValueError("synthetic concatenation failure")

                local.setattr(
                    protocol, "struct", SimpleNamespace(pack=lambda *args: Prefix())
                )
            if kind == "success":
                assert boundary._call("install", {}) == {"state": "accepted"}
            else:
                with pytest.raises(UnifiOperationError, match="request failed"):
                    boundary._call("install", {})
        assert len(connections) == count + 1  # never retry
        if kind in {"pack", "concat"}:
            assert events == ["connect"]
        elif kind == "callback":
            assert events == ["connect", "dispatch"]
        else:
            assert events == ["connect", "dispatch", ("send", expected_frame)]
        assert evidence["value"].target.milestones["installation"] is (
            Milestone.UNCERTAIN
            if kind in {"send", "success"}
            else Milestone.NOT_ATTEMPTED
        )
