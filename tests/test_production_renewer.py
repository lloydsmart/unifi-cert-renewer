import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

import production_renewer
import secure_file
from unifi_cert_renewer import InstallationStageResult
from unifi_client import UnifiClient, prepare_certificate_import
from unifi_executor_client import SocketUnifiExecutionBoundary
from unifi_tls import LiveTLSEndpoint

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def config_value(policy):
    return {
        "certificate_policy": {
            "expected_spki_sha256": policy.expected_spki_sha256,
            "subject": policy.subject,
            "dns_sans": list(policy.dns_sans),
            "ip_sans": list(policy.ip_sans),
        },
        "opnsense": {
            "base_url": "https://opnsense.test",
            "timeout_seconds": 30,
            "tls_ca_name": "opnsense-ca.pem",
        },
        "issuing_ca_description": "Internal CA",
        "certificate_description": "UniFi HTTPS certificate",
        "trusted_ca_name": "issuing-ca.pem",
        "lifetime_days": 30,
        "digest": "sha384",
        "live_tls": {
            "address": "192.0.2.10",
            "server_hostname": "unifi.test",
            "port": 8443,
            "timeout_seconds": 60,
            "attempt_timeout_seconds": 5,
            "retry_delay_seconds": 0.5,
            "max_attempts": 120,
        },
    }


def parsed_config(installation_material):
    return production_renewer._parse_config(
        config_value(installation_material.request.policy)
    )


def test_production_path_constructs_fixed_socket_boundary():
    client = production_renewer.build_production_unifi_client()

    assert isinstance(client, UnifiClient)
    assert isinstance(client._boundary, SocketUnifiExecutionBoundary)
    assert set(vars(client._boundary)) == {"_exclusive", "_installed"}


def test_loads_strict_configuration_from_fixed_secure_file(
    installation_material, monkeypatch, tmp_path
):
    monkeypatch.setattr(secure_file, "SECURE_FILE_ROOT", str(tmp_path))
    config_file = tmp_path / production_renewer.CONFIG_NAME
    config_file.write_text(
        json.dumps(config_value(installation_material.request.policy)), encoding="utf-8"
    )
    config_file.chmod(0o644)

    config = production_renewer.load_production_config()

    assert config.policy == installation_material.request.policy
    assert config.opnsense_base_url == "https://opnsense.test"
    assert config.trusted_ca_name == "issuing-ca.pem"
    assert config.live_endpoint == LiveTLSEndpoint("192.0.2.10", "unifi.test", 8443)


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda value: value.update(extra="rejected"), "fields"),
        (
            lambda value: value["certificate_policy"].update(
                expected_spki_sha256="not-a-fingerprint"
            ),
            "certificate_policy",
        ),
        (
            lambda value: value["opnsense"].update(base_url="http://unsafe.example"),
            "base_url",
        ),
        (lambda value: value.update(trusted_ca_name="../outside"), "trusted_ca_name"),
        (lambda value: value.update(digest="md5"), "signing policy"),
        (
            lambda value: value["live_tls"].update(address="unsafe\nmarker"),
            "live_tls",
        ),
    ],
)
def test_rejects_unsafe_configuration_without_reflecting_values(
    installation_material, mutate, message
):
    value = config_value(installation_material.request.policy)
    mutate(value)

    with pytest.raises(
        production_renewer.ProductionConfigurationError, match=message
    ) as raised:
        production_renewer._parse_config(value)

    assert "unsafe\nmarker" not in str(raised.value)
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
        "Usage: production_renewer.py {inspect|csr|prepare|install}\n"
    )


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
        production_renewer, "build_production_unifi_client", PublicClient
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
        production_renewer, "build_production_unifi_client", lambda: unifi
    )
    monkeypatch.setattr(
        production_renewer, "_read_trusted_ca", lambda name: b"trusted-ca"
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
    assert (calls[0]["live_endpoint"] is not None) is (mode == "install")


def test_install_requires_live_verification_before_api_or_mutation(
    installation_material, monkeypatch
):
    config = replace(
        parsed_config(installation_material), live_endpoint=None, readiness=None
    )
    monkeypatch.setattr(production_renewer, "load_production_config", lambda: config)
    monkeypatch.setattr(
        production_renewer, "build_production_unifi_client", lambda: object()
    )
    monkeypatch.setattr(
        production_renewer, "_read_trusted_ca", lambda name: b"trusted-ca"
    )
    monkeypatch.setattr(
        production_renewer,
        "OPNsenseClient",
        lambda *args, **kwargs: pytest.fail("API client must not be constructed"),
    )

    with pytest.raises(
        production_renewer.ProductionRunError, match="requires live TLS"
    ):
        production_renewer.run_one_shot("install")


def test_missing_private_api_secrets_are_safely_normalized(
    installation_material, monkeypatch, tmp_path
):
    config = parsed_config(installation_material)
    ca_file = tmp_path / config.trusted_ca_name
    ca_file.write_bytes(installation_material.request.trusted_ca_data)
    ca_file.chmod(0o644)
    monkeypatch.setattr(secure_file, "SECURE_FILE_ROOT", str(tmp_path))
    monkeypatch.setattr(production_renewer, "load_production_config", lambda: config)
    monkeypatch.setattr(
        production_renewer, "build_production_unifi_client", lambda: object()
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
    ca_file = tmp_path / config.trusted_ca_name
    ca_file.write_bytes(installation_material.request.trusted_ca_data)
    ca_file.chmod(0o644)
    api_key = tmp_path / "opnsense-api-key"
    api_key.write_text("not-logged", encoding="utf-8")
    api_key.chmod(0o644)
    api_secret = tmp_path / "opnsense-api-secret"
    api_secret.write_text("also-not-logged", encoding="utf-8")
    api_secret.chmod(0o600)
    monkeypatch.setattr(secure_file, "SECURE_FILE_ROOT", str(tmp_path))
    monkeypatch.setattr(production_renewer, "load_production_config", lambda: config)
    monkeypatch.setattr(
        production_renewer, "build_production_unifi_client", lambda: object()
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

    assert "FROM python:3.12-slim-bookworm@sha256:" in dockerfile
    assert "USER 1000:1000" in dockerfile
    assert "src/unifi_executor.py" not in dockerfile
    assert "src/unifi_executor_files.py" not in dockerfile
    assert "src/unifi_process.py" not in dockerfile
    assert 'user: "1000:1000"' in compose
    assert '      - "984"' in compose
    assert "source: /run/unifi-cert-renewer" in compose
    assert "target: /run/unifi-cert-renewer" in compose
    assert "cap_drop:\n      - ALL" in compose
    assert "no-new-privileges:true" in compose
    for source in (
        "opnsense_client.py",
        "production_renewer.py",
        "unifi_cert_renewer.py",
        "unifi_executor_client.py",
        "unifi_tls.py",
    ):
        assert f"!src/{source}" in dockerignore
    for forbidden in (
        "/config",
        "unifi-keystore-password",
        "/var/run/docker.sock",
        "restart: always",
    ):
        assert forbidden not in compose
