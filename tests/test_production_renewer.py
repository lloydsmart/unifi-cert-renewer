import json
import os
import subprocess
import sys
import threading
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from conftest import policy_for
from cryptography.hazmat.primitives import serialization

import production_renewer
import secure_file
from unifi_cert_renewer import InstallationStageResult
from unifi_client import PublicKeystoreState, UnifiClient, prepare_certificate_import
from unifi_executor_client import SocketUnifiExecutionBoundary

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def config_value(policy):
    return {
        "expected_spki_sha256": policy.expected_spki_sha256,
        "opnsense": {
            "base_url": "https://opnsense.test",
            "timeout_seconds": 30,
            "tls_ca_name": "opnsense-ca.pem",
        },
        "certificate_description": "UniFi HTTPS certificate",
    }


def parsed_config(installation_material):
    return production_renewer._parse_config(
        config_value(installation_material.request.policy),
        replace(policy_for(installation_material), lifetime_days=397),
    )


def public_state_expiring_at(installation_material, not_valid_after):
    certificate = installation_material.issue(
        not_before=not_valid_after - timedelta(days=60),
        not_after=not_valid_after,
    )
    return PublicKeystoreState(
        installation_material.request.before.keytool_output,
        (certificate.public_bytes(serialization.Encoding.DER),),
    )


def test_production_path_constructs_fixed_socket_boundary(installation_material):
    client = production_renewer.build_production_unifi_client(
        policy_for(installation_material)
    )

    assert isinstance(client, UnifiClient)
    assert isinstance(client._boundary, SocketUnifiExecutionBoundary)
    assert set(vars(client._boundary)) == {"_policy", "_exclusive", "_installed"}


def test_loads_strict_configuration_from_fixed_secure_file(
    installation_material, monkeypatch, tmp_path
):
    monkeypatch.setattr(secure_file, "SECURE_FILE_ROOT", str(tmp_path))
    config_file = tmp_path / production_renewer.CONFIG_NAME
    config_file.write_text(
        json.dumps(config_value(installation_material.request.policy)), encoding="utf-8"
    )
    config_file.chmod(0o644)

    monkeypatch.setattr(
        production_renewer,
        "load_policy",
        lambda: replace(policy_for(installation_material), lifetime_days=397),
    )
    config = production_renewer.load_production_config()

    assert config.policy == installation_material.request.policy
    assert config.opnsense_base_url == "https://opnsense.test"
    assert config.authority.lifetime_days == 397
    assert config.renew_before_days == 30


@pytest.mark.parametrize("renew_before_days", [1, 45, 396])
def test_accepts_explicit_renewal_window(installation_material, renew_before_days):
    value = config_value(installation_material.request.policy)
    value["renew_before_days"] = renew_before_days

    assert (
        production_renewer._parse_config(
            value, replace(policy_for(installation_material), lifetime_days=397)
        ).renew_before_days
        == renew_before_days
    )


@pytest.mark.parametrize("renew_before_days", [0, -1, True, 1.5, "30", 398, 999])
def test_rejects_invalid_renewal_window(installation_material, renew_before_days):
    value = config_value(installation_material.request.policy)
    value["renew_before_days"] = renew_before_days

    with pytest.raises(
        production_renewer.ProductionConfigurationError, match="renewal policy"
    ):
        production_renewer._parse_config(value, policy_for(installation_material))


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda value: value.update(extra="rejected"), "fields"),
        (lambda value: value.update(expected_spki_sha256="bad"), "observed public key"),
        (
            lambda value: value["opnsense"].update(base_url="http://unsafe.example"),
            "base_url",
        ),
        (lambda value: value.update(trusted_ca_name="../outside"), "fields"),
        (lambda value: value.update(digest="md5"), "fields"),
        (lambda value: value.update(subject="CN=other"), "fields"),
    ],
)
def test_rejects_unsafe_configuration_without_reflecting_values(
    installation_material, mutate, message
):
    value = config_value(installation_material.request.policy)
    mutate(value)
    with pytest.raises(ValueError, match=message) as raised:
        production_renewer._parse_config(value, policy_for(installation_material))
    assert "../outside" not in str(raised.value)


def test_missing_configuration_has_bounded_error(monkeypatch, tmp_path):
    monkeypatch.setattr(secure_file, "SECURE_FILE_ROOT", str(tmp_path))

    with pytest.raises(
        production_renewer.ProductionConfigurationError,
        match="could not be read safely",
    ) as raised:
        production_renewer.load_production_config()

    assert str(tmp_path) not in str(raised.value)


def test_group_writable_configuration_is_rejected(monkeypatch, tmp_path):
    monkeypatch.setattr(secure_file, "SECURE_FILE_ROOT", str(tmp_path))
    config_file = tmp_path / production_renewer.CONFIG_NAME
    config_file.write_text("{}", encoding="utf-8")
    config_file.chmod(0o664)

    with pytest.raises(
        production_renewer.ProductionConfigurationError,
        match="could not be read safely",
    ):
        production_renewer.load_production_config()


@pytest.mark.parametrize("arguments", [[], ["unknown"], ["inspect", "csr"]])
def test_entrypoint_accepts_exactly_one_known_mode(arguments, capsys):
    assert production_renewer.main(arguments) == 2
    assert capsys.readouterr().err == (
        "Usage: production_renewer.py {inspect|csr|prepare|install|renew}\n"
    )


@pytest.fixture(autouse=True)
def lifecycle_directory(tmp_path, monkeypatch):
    directory = tmp_path / "lifecycle"
    directory.mkdir(mode=0o750)
    directory.chmod(0o750)
    lock = directory / "renewal.lock"
    lock.touch(mode=0o660)
    lock.chmod(0o660)
    monkeypatch.setattr(production_renewer, "LIFECYCLE_DIRECTORY", str(directory))
    monkeypatch.setattr(production_renewer, "LIFECYCLE_OWNER_UID", os.geteuid())
    monkeypatch.setattr(production_renewer, "LIFECYCLE_GROUP_GID", os.getegid())
    return directory


@pytest.mark.parametrize("mode", ["prepare", "install", "renew"])
def test_busy_lifecycle_rejects_before_configuration_or_signing(
    lifecycle_directory, monkeypatch, mode
):
    lock = lifecycle_directory / "renewal.lock"
    original = lock.stat()
    monkeypatch.setattr(
        production_renewer,
        "load_production_config",
        lambda: pytest.fail("busy worker must not inspect or sign"),
    )
    with production_renewer._lifecycle_lock():
        assert production_renewer.run_one_shot(mode) == {
            "mode": mode,
            "state": "busy",
            "renewal_complete": False,
        }
    assert lock.stat().st_ino == original.st_ino
    assert lock.stat().st_size == 0


def test_busy_entrypoint_reports_temporary_failure(
    lifecycle_directory, monkeypatch, capsys
):
    with production_renewer._lifecycle_lock():
        assert production_renewer.main(["renew"]) == 75
    assert json.loads(capsys.readouterr().out) == {
        "mode": "renew",
        "state": "busy",
        "renewal_complete": False,
    }


@pytest.mark.parametrize(
    ("first", "second"),
    [("renew", "renew"), ("prepare", "install"), ("install", "prepare")],
)
def test_overlapping_lifecycles_and_success_release(
    installation_material, monkeypatch, first, second
):
    config = replace(parsed_config(installation_material), renew_before_days=45)
    now = installation_material.now
    due_state = public_state_expiring_at(
        installation_material, now + timedelta(days=30)
    )
    plan = prepare_certificate_import(
        installation_material.request, now=installation_material.now
    )
    entered = threading.Event()
    release = threading.Event()
    events = []
    outcomes = []

    class DueClient:
        def inspect_current(self, policy):
            events.append("inspect")
            assert policy == config.policy
            return due_state

    unifi = DueClient()

    def load_config():
        events.append("config")
        return config

    def build_client(authority):
        events.append("client")
        return unifi

    def opnsense_client(*args, **kwargs):
        events.append("opnsense")
        return object()

    def sign_once(**kwargs):
        events.append("sign")
        entered.set()
        assert release.wait(timeout=5)
        installed = SimpleNamespace() if kwargs["install"] else None
        state = "renewal_complete" if installed is not None else "prepared"
        return InstallationStageResult(
            state, installation_material.request, plan, installed
        )

    def first_run():
        try:
            outcomes.append(production_renewer.run_one_shot(first, now=now))
        except BaseException as error:
            outcomes.append(error)

    monkeypatch.setattr(production_renewer, "load_production_config", load_config)
    monkeypatch.setattr(
        production_renewer, "build_production_unifi_client", build_client
    )
    monkeypatch.setattr(production_renewer, "OPNsenseClient", opnsense_client)
    monkeypatch.setattr(production_renewer, "run_to_installation", sign_once)
    worker = threading.Thread(target=first_run)
    worker.start()
    try:
        assert entered.wait(timeout=5)
        before_busy = events.copy()
        assert production_renewer.run_one_shot(second, now=now) == {
            "mode": second,
            "state": "busy",
            "renewal_complete": False,
        }
        assert events == before_busy
    finally:
        release.set()
        worker.join(timeout=5)
    assert not worker.is_alive()
    assert len(outcomes) == 1 and isinstance(outcomes[0], dict)
    assert outcomes[0]["state"] in {"prepared", "renewal_complete"}
    assert production_renewer.run_one_shot(second, now=now)["state"] in {
        "prepared",
        "renewal_complete",
    }
    assert events.count("sign") == 2


def test_crashed_worker_releases_lifecycle_lock(lifecycle_directory):
    code = """
import os
import sys
sys.path.insert(0, sys.argv[1])
import production_renewer
production_renewer.LIFECYCLE_DIRECTORY = sys.argv[2]
production_renewer.LIFECYCLE_OWNER_UID = os.geteuid()
production_renewer.LIFECYCLE_GROUP_GID = os.getegid()
with production_renewer._lifecycle_lock():
    print("locked", flush=True)
    sys.stdin.read(1)
"""
    child = subprocess.Popen(
        [
            sys.executable,
            "-c",
            code,
            str(REPOSITORY_ROOT / "src"),
            str(lifecycle_directory),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert child.stdout.readline().strip() == "locked"
        with (
            pytest.raises(production_renewer._LifecycleBusy),
            production_renewer._lifecycle_lock(),
        ):
            pytest.fail("concurrent worker acquired the lock")
        child.kill()
        child.wait(timeout=5)
        with production_renewer._lifecycle_lock():
            pass
        assert (lifecycle_directory / "renewal.lock").exists()
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5)
        child.stdin.close()
        child.stdout.close()


def test_pre_signing_failure_releases_lifecycle_lock(monkeypatch):
    def fail_config():
        raise ValueError("synthetic failure")

    monkeypatch.setattr(production_renewer, "load_production_config", fail_config)
    with pytest.raises(production_renewer.ProductionRunError):
        production_renewer.run_one_shot("renew")
    with production_renewer._lifecycle_lock():
        pass


def test_missing_lifecycle_lock_fails_without_creating_it(
    lifecycle_directory, monkeypatch
):
    lock = lifecycle_directory / "renewal.lock"
    lock.unlink()
    monkeypatch.setattr(
        production_renewer,
        "load_production_config",
        lambda: pytest.fail("missing lock must stop before inspection"),
    )
    with pytest.raises(production_renewer.ProductionRunError, match="lock unavailable"):
        production_renewer.run_one_shot("renew")
    assert not lock.exists()


def test_unsafe_lifecycle_lock_rejected(lifecycle_directory):
    lock = lifecycle_directory / "renewal.lock"
    lock.unlink()
    lock.symlink_to(lifecycle_directory / "target")
    with (
        pytest.raises(production_renewer.ProductionRunError, match="lock unavailable"),
        production_renewer._lifecycle_lock(),
    ):
        pytest.fail("symlink must not be followed")


@pytest.mark.parametrize(
    "damage", ["directory_mode", "file_mode", "hardlink", "owner", "group"]
)
def test_invalid_host_lock_metadata_fails_closed(
    lifecycle_directory, monkeypatch, damage
):
    lock = lifecycle_directory / "renewal.lock"
    if damage == "directory_mode":
        lifecycle_directory.chmod(0o770)
    elif damage == "file_mode":
        lock.chmod(0o664)
    elif damage == "hardlink":
        os.link(lock, lifecycle_directory / "second-link")
    elif damage == "owner":
        monkeypatch.setattr(production_renewer, "LIFECYCLE_OWNER_UID", os.geteuid() + 1)
    else:
        monkeypatch.setattr(production_renewer, "LIFECYCLE_GROUP_GID", os.getegid() + 1)
    monkeypatch.setattr(
        production_renewer,
        "load_production_config",
        lambda: pytest.fail("unsafe lock must stop before inspection"),
    )
    with pytest.raises(production_renewer.ProductionRunError, match="lock unavailable"):
        production_renewer.run_one_shot("renew")


def test_lock_path_replacement_after_flock_fails_before_renewal(
    lifecycle_directory, monkeypatch
):
    lock = lifecycle_directory / "renewal.lock"
    old_inode = lock.stat().st_ino
    original_flock = production_renewer.fcntl.flock

    def replace_after_flock(fd, operation):
        original_flock(fd, operation)
        replacement = lifecycle_directory / "replacement"
        replacement.touch(mode=0o660)
        replacement.chmod(0o660)
        os.replace(replacement, lock)

    monkeypatch.setattr(production_renewer.fcntl, "flock", replace_after_flock)
    monkeypatch.setattr(
        production_renewer,
        "load_production_config",
        lambda: pytest.fail("replaced lock must stop before inspection"),
    )
    with pytest.raises(production_renewer.ProductionRunError, match="lock unavailable"):
        production_renewer.run_one_shot("renew")
    assert lock.stat().st_ino != old_inode


def test_entrypoint_accepts_renew(monkeypatch, capsys):
    monkeypatch.setattr(
        production_renewer,
        "run_one_shot",
        lambda mode: {"mode": mode, "state": "renewal_not_due"},
    )

    assert production_renewer.main(["renew"]) == 0
    assert json.loads(capsys.readouterr().out) == {
        "mode": "renew",
        "state": "renewal_not_due",
    }


@pytest.mark.parametrize("mode", ["inspect", "csr"])
def test_public_modes_use_only_fixed_socket_client(
    installation_material, monkeypatch, mode
):
    config = parsed_config(installation_material)
    calls = []

    class PublicClient:
        def inspect_current(self, policy):
            calls.append(("inspect", policy))
            return installation_material.request.before

        def request_csr(self, policy):
            calls.append(("csr", policy))
            return installation_material.request.csr_pem

    monkeypatch.setattr(production_renewer, "load_production_config", lambda: config)
    monkeypatch.setattr(
        production_renewer,
        "build_production_unifi_client",
        lambda authority: PublicClient(),
    )

    result = production_renewer.run_one_shot(mode)

    assert result["mode"] == mode
    assert calls == [(mode, config.policy)]


@pytest.mark.parametrize("mode", ["prepare", "install"])
def test_state_changing_modes_call_existing_orchestration_once(
    installation_material, monkeypatch, mode
):
    config = parsed_config(installation_material)
    plan = prepare_certificate_import(
        installation_material.request, now=installation_material.now
    )
    installed = SimpleNamespace() if mode == "install" else None
    state = "renewal_complete" if mode == "install" else "prepared"
    result = InstallationStageResult(
        state, installation_material.request, plan, installed
    )
    calls = []
    unifi = object()
    opnsense = object()

    monkeypatch.setattr(production_renewer, "load_production_config", lambda: config)
    monkeypatch.setattr(
        production_renewer, "build_production_unifi_client", lambda authority: unifi
    )
    monkeypatch.setattr(
        production_renewer, "OPNsenseClient", lambda *args, **kwargs: opnsense
    )
    monkeypatch.setattr(
        production_renewer,
        "run_to_installation",
        lambda **kwargs: calls.append(kwargs) or result,
    )

    output = production_renewer.run_one_shot(mode)

    assert output["state"] == state
    assert len(calls) == 1
    assert calls[0]["unifi"] is unifi
    assert calls[0]["opnsense"] is opnsense
    assert calls[0]["install"] is (mode == "install")
    assert calls[0]["trusted_ca_data"] == config.authority.ca_pem


@pytest.mark.parametrize(
    ("offset", "expected"),
    [
        (timedelta(0), True),
        (timedelta(microseconds=1), True),
        (timedelta(microseconds=-1), False),
        (timedelta(days=-100), False),
        (timedelta(days=31), True),
    ],
)
def test_renewal_threshold_uses_exact_timestamps(
    installation_material, offset, expected
):
    certificate = production_renewer.inspect_public_keystore_state(
        installation_material.request.before
    ).certificate
    now = certificate.not_valid_after - timedelta(days=30) + offset

    assert production_renewer._renewal_is_due(certificate, 30, now=now) is expected


def test_renew_not_due_is_read_only(installation_material, monkeypatch):
    config = parsed_config(installation_material)
    now = installation_material.now
    state = public_state_expiring_at(installation_material, now + timedelta(days=60))
    inspections = []

    class ReadOnlyClient:
        def inspect_current(self, policy):
            inspections.append(policy)
            return state

        def request_csr(self, policy):
            pytest.fail("CSR must not be requested when renewal is not due")

        def install_certificate(self, request):
            pytest.fail("certificate must not be installed when renewal is not due")

    monkeypatch.setattr(production_renewer, "load_production_config", lambda: config)
    monkeypatch.setattr(
        production_renewer,
        "build_production_unifi_client",
        lambda authority: ReadOnlyClient(),
    )
    monkeypatch.setattr(
        production_renewer,
        "OPNsenseClient",
        lambda *args, **kwargs: pytest.fail(
            "OPNsense client must not be constructed when renewal is not due"
        ),
    )
    monkeypatch.setattr(
        production_renewer,
        "run_to_installation",
        lambda **kwargs: pytest.fail(
            "renewal orchestration must not run when renewal is not due"
        ),
    )

    output = production_renewer.run_one_shot("renew", now=now)

    assert inspections == [config.policy]
    assert output == {
        "mode": "renew",
        "state": "renewal_not_due",
        "renewal_due": False,
        "renewal_complete": False,
        "renew_before_days": 30,
        "certificate": production_renewer._certificate_output(
            production_renewer.inspect_public_keystore_state(state).certificate
        ),
    }


def test_renew_inspection_failure_stops_before_signing(
    installation_material, monkeypatch
):
    config = parsed_config(installation_material)

    class InvalidInspectionClient:
        def inspect_current(self, policy):
            return object()

    monkeypatch.setattr(production_renewer, "load_production_config", lambda: config)
    monkeypatch.setattr(
        production_renewer,
        "build_production_unifi_client",
        lambda authority: InvalidInspectionClient(),
    )
    monkeypatch.setattr(
        production_renewer,
        "OPNsenseClient",
        lambda *args, **kwargs: pytest.fail("API client must not be constructed"),
    )
    monkeypatch.setattr(
        production_renewer,
        "run_to_installation",
        lambda **kwargs: pytest.fail("renewal orchestration must not run"),
    )

    with pytest.raises(
        production_renewer.ProductionRunError, match="stopped during renew"
    ):
        production_renewer.run_one_shot("renew", now=installation_material.now)


def test_due_renew_calls_existing_installation_orchestration_once(
    installation_material, monkeypatch
):
    config = replace(parsed_config(installation_material), renew_before_days=45)
    now = installation_material.now
    state = public_state_expiring_at(installation_material, now + timedelta(days=45))
    plan = prepare_certificate_import(
        installation_material.request, now=installation_material.now
    )
    result = InstallationStageResult(
        "renewal_complete",
        installation_material.request,
        plan,
        SimpleNamespace(),
    )
    calls = []
    opnsense = object()

    class DueClient:
        def inspect_current(self, policy):
            assert policy == config.policy
            return state

    unifi = DueClient()
    monkeypatch.setattr(production_renewer, "load_production_config", lambda: config)
    monkeypatch.setattr(
        production_renewer, "build_production_unifi_client", lambda authority: unifi
    )
    monkeypatch.setattr(
        production_renewer, "OPNsenseClient", lambda *args, **kwargs: opnsense
    )
    monkeypatch.setattr(
        production_renewer,
        "run_to_installation",
        lambda **kwargs: calls.append(kwargs) or result,
    )

    output = production_renewer.run_one_shot("renew", now=now)

    assert len(calls) == 1
    assert calls[0] == {
        "unifi": unifi,
        "opnsense": opnsense,
        "policy": config.policy,
        "trusted_ca_data": config.authority.ca_pem,
        "ca_description": config.authority.issuing_ca_description,
        "certificate_description": config.certificate_description,
        "lifetime_days": config.authority.lifetime_days,
        "digest": config.authority.signing_digest,
        "issued_signature_oid": config.authority.issued_signature_oid,
        "install": True,
        "minimum_remaining_days": 45,
    }
    assert output["mode"] == "renew"
    assert output["state"] == "renewal_complete"
    assert output["renewal_due"] is True
    assert output["renewal_complete"] is True
    assert output["renew_before_days"] == 45


def test_direct_install_does_not_apply_renewal_threshold(
    installation_material, monkeypatch
):
    config = replace(parsed_config(installation_material), renew_before_days=1)
    result = SimpleNamespace(
        state="renewal_complete",
        renewal_complete=True,
        installed=SimpleNamespace(),
        plan=SimpleNamespace(
            issued=production_renewer.inspect_public_keystore_state(
                installation_material.request.before
            ).certificate
        ),
    )
    calls = []
    monkeypatch.setattr(production_renewer, "load_production_config", lambda: config)
    monkeypatch.setattr(
        production_renewer, "build_production_unifi_client", lambda authority: object()
    )
    monkeypatch.setattr(
        production_renewer, "OPNsenseClient", lambda *args, **kwargs: object()
    )
    monkeypatch.setattr(
        production_renewer,
        "run_to_installation",
        lambda **kwargs: calls.append(kwargs) or result,
    )

    output = production_renewer.run_one_shot("install")

    assert len(calls) == 1
    assert calls[0]["install"] is True
    assert output["mode"] == "install"


def test_missing_private_api_secrets_are_safely_normalized(
    installation_material, monkeypatch, tmp_path
):
    config = parsed_config(installation_material)
    monkeypatch.setattr(secure_file, "SECURE_FILE_ROOT", str(tmp_path))
    monkeypatch.setattr(production_renewer, "load_production_config", lambda: config)
    monkeypatch.setattr(
        production_renewer, "build_production_unifi_client", lambda authority: object()
    )

    with pytest.raises(
        production_renewer.ProductionRunError,
        match="OPNsense client configuration",
    ) as raised:
        production_renewer.run_one_shot("prepare")

    assert str(tmp_path) not in str(raised.value)


def test_unsafe_api_secret_permissions_are_safely_normalized(
    installation_material, monkeypatch, tmp_path
):
    config = replace(parsed_config(installation_material), opnsense_tls_ca_name=None)
    api_key = tmp_path / "opnsense-api-key"
    api_key.write_text("not-logged", encoding="utf-8")
    api_key.chmod(0o644)
    api_secret = tmp_path / "opnsense-api-secret"
    api_secret.write_text("also-not-logged", encoding="utf-8")
    api_secret.chmod(0o600)
    monkeypatch.setattr(secure_file, "SECURE_FILE_ROOT", str(tmp_path))
    monkeypatch.setattr(production_renewer, "load_production_config", lambda: config)
    monkeypatch.setattr(
        production_renewer, "build_production_unifi_client", lambda authority: object()
    )

    with pytest.raises(
        production_renewer.ProductionRunError,
        match="OPNsense client configuration",
    ) as raised:
        production_renewer.run_one_shot("prepare")

    assert "not-logged" not in str(raised.value)
    assert "also-not-logged" not in str(raised.value)


def test_renewer_image_and_compose_preserve_least_privilege_metadata():
    dockerfile = (REPOSITORY_ROOT / "deployment/renewer/Dockerfile").read_text()
    compose = (REPOSITORY_ROOT / "deployment/renewer/compose.example.yaml").read_text()
    dockerignore = (REPOSITORY_ROOT / ".dockerignore").read_text()

    assert "FROM python:3.14-slim-bookworm@sha256:" in dockerfile
    assert "USER 1000:1000" in dockerfile
    assert "src/unifi_executor.py" not in dockerfile
    assert "src/unifi_executor_files.py" not in dockerfile
    assert "src/unifi_process.py" not in dockerfile
    assert "src/renewal_policy.py" in dockerfile
    executor_dockerfile = (REPOSITORY_ROOT / "deployment/unifi/Dockerfile").read_text()
    assert "src/renewal_policy.py" in executor_dockerfile
    assert "src/unifi_tls.py" in executor_dockerfile
    assert 'user: "1000:1000"' in compose
    assert '      - "984"' in compose
    assert "source: /run/unifi-cert-renewer" in compose
    assert "target: /run/unifi-cert-renewer" in compose
    assert "target: /run/unifi-cert-renewer-policy" in compose
    assert "read_only: true" in compose
    assert "cap_drop:\n      - ALL" in compose
    assert "no-new-privileges:true" in compose
    for source in (
        "opnsense_client.py",
        "production_renewer.py",
        "unifi_cert_renewer.py",
        "unifi_executor_client.py",
        "unifi_tls.py",
        "renewal_policy.py",
    ):
        assert f"!src/{source}" in dockerignore
    for forbidden in (
        "/config",
        "unifi-keystore-password",
        "/var/run/docker.sock",
        "restart: always",
    ):
        assert forbidden not in compose


@pytest.mark.parametrize("window", [30, 31])
def test_renew_only_rejects_threshold_at_or_above_lifetime_before_inspection(
    installation_material, monkeypatch, window
):
    value = config_value(installation_material.request.policy)
    value["renew_before_days"] = window
    config = production_renewer._parse_config(value, policy_for(installation_material))
    monkeypatch.setattr(production_renewer, "load_production_config", lambda: config)
    monkeypatch.setattr(
        production_renewer,
        "build_production_unifi_client",
        lambda authority: pytest.fail("renew must reject before UniFi inspection"),
    )
    with pytest.raises(
        production_renewer.ProductionRunError, match="configuration validation"
    ):
        production_renewer.run_one_shot("renew")


@pytest.mark.parametrize("window", [30, 31])
@pytest.mark.parametrize("mode", ["inspect", "csr", "prepare", "install"])
def test_manual_modes_allow_threshold_at_or_above_lifetime(
    installation_material, monkeypatch, window, mode
):
    value = config_value(installation_material.request.policy)
    value["renew_before_days"] = window
    config = production_renewer._parse_config(value, policy_for(installation_material))
    request = installation_material.request
    plan = prepare_certificate_import(request)
    result = InstallationStageResult(
        "renewal_complete" if mode == "install" else "prepared",
        request,
        plan,
        SimpleNamespace() if mode == "install" else None,
    )

    class ManualClient:
        def inspect_current(self, policy):
            return request.before

        def request_csr(self, policy):
            return request.csr_pem

    monkeypatch.setattr(production_renewer, "load_production_config", lambda: config)
    monkeypatch.setattr(
        production_renewer,
        "build_production_unifi_client",
        lambda authority: ManualClient(),
    )
    monkeypatch.setattr(production_renewer, "OPNsenseClient", lambda *a, **kw: object())
    monkeypatch.setattr(production_renewer, "run_to_installation", lambda **kw: result)
    assert production_renewer.run_one_shot(mode)["mode"] == mode


def test_renewal_window_one_day_below_lifetime_proceeds(
    installation_material, monkeypatch
):
    value = config_value(installation_material.request.policy)
    value["renew_before_days"] = 29
    config = production_renewer._parse_config(value, policy_for(installation_material))
    request = installation_material.request
    due_state = public_state_expiring_at(
        installation_material, installation_material.now + timedelta(days=20)
    )
    result = InstallationStageResult(
        "renewal_complete",
        request,
        prepare_certificate_import(request),
        SimpleNamespace(),
    )

    class DueClient:
        def inspect_current(self, policy):
            return due_state

    calls = []
    monkeypatch.setattr(production_renewer, "load_production_config", lambda: config)
    monkeypatch.setattr(
        production_renewer,
        "build_production_unifi_client",
        lambda authority: DueClient(),
    )
    monkeypatch.setattr(production_renewer, "OPNsenseClient", lambda *a, **kw: object())
    monkeypatch.setattr(
        production_renewer,
        "run_to_installation",
        lambda **kwargs: calls.append(kwargs) or result,
    )
    assert production_renewer.run_one_shot("renew", now=installation_material.now)[
        "renewal_complete"
    ]
    assert calls[0]["minimum_remaining_days"] == 29
