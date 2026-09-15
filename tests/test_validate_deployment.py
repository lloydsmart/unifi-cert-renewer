import copy
import importlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
validator = importlib.import_module("validate_deployment")


def valid_compose() -> dict[str, object]:
    return {
        "services": {
            "renewer": {
                "image": validator.EXPECTED_RENEWER_IMAGE,
                "user": "1000:1000",
                "group_add": ["984"],
                "read_only": True,
                "cap_drop": ["ALL"],
                "security_opt": ["no-new-privileges:true"],
                "restart": "no",
                "pids_limit": 64,
                "tmpfs": [validator.EXPECTED_TMPFS],
                "volumes": [
                    {
                        "type": "bind",
                        "source": "/run/unifi-cert-renewer",
                        "target": "/run/unifi-cert-renewer",
                        "read_only": True,
                    },
                    {
                        "type": "bind",
                        "source": validator.EXPECTED_SECRETS_DIRECTORY,
                        "target": "/run/secrets",
                        "read_only": True,
                    },
                ],
                "networks": {"unifi": None},
            }
        },
        "networks": {
            "unifi": {"name": validator.EXPECTED_NETWORK_NAME, "external": True}
        },
    }


def test_valid_compose_boundary_passes() -> None:
    validator.validate_compose(valid_compose())


def test_compose_rejects_different_image() -> None:
    document = valid_compose()
    document["services"]["renewer"]["image"] = "example/renewer:latest"  # type: ignore[index]

    with pytest.raises(validator.DeploymentValidationError):
        validator.validate_compose(document)


def test_compose_rejects_missing_image() -> None:
    document = valid_compose()
    del document["services"]["renewer"]["image"]  # type: ignore[index]

    with pytest.raises(validator.DeploymentValidationError):
        validator.validate_compose(document)


@pytest.mark.parametrize(
    ("key", "unsafe_value"),
    [
        ("user", "0:0"),
        ("group_add", ["984", "999"]),
        ("read_only", False),
        ("cap_drop", []),
        ("security_opt", []),
        ("restart", "always"),
        ("pids_limit", 0),
        ("tmpfs", ["/tmp:rw"]),
    ],
)
def test_compose_rejects_weakened_service_setting(
    key: str, unsafe_value: object
) -> None:
    document = valid_compose()
    document["services"]["renewer"][key] = unsafe_value  # type: ignore[index]

    with pytest.raises(validator.DeploymentValidationError):
        validator.validate_compose(document)


def test_compose_rejects_additional_or_sensitive_mount() -> None:
    document = valid_compose()
    document["services"]["renewer"]["volumes"].append(  # type: ignore[index,union-attr]
        {
            "type": "bind",
            "source": "/var/run/docker.sock",
            "target": "/var/run/docker.sock",
            "read_only": True,
        }
    )

    with pytest.raises(validator.DeploymentValidationError):
        validator.validate_compose(document)


def test_compose_rejects_writable_mount() -> None:
    document = valid_compose()
    document["services"]["renewer"]["volumes"][0]["read_only"] = False  # type: ignore[index]

    with pytest.raises(validator.DeploymentValidationError):
        validator.validate_compose(document)


def test_compose_rejects_nonexternal_or_additional_network() -> None:
    document = valid_compose()
    document["networks"]["unifi"]["external"] = False  # type: ignore[index]

    with pytest.raises(validator.DeploymentValidationError):
        validator.validate_compose(document)

    document = valid_compose()
    document["services"]["renewer"]["networks"]["other"] = None  # type: ignore[index]

    with pytest.raises(validator.DeploymentValidationError):
        validator.validate_compose(document)


def test_valid_acl_passes(tmp_path: Path) -> None:
    acl = tmp_path / "ACL.xml"
    acl.write_text(
        "<acl><rule><patterns>"
        + "".join(
            f"<pattern>{pattern}</pattern>"
            for pattern in validator.EXPECTED_ACL_PATTERNS
        )
        + "</patterns></rule></acl>",
        encoding="utf-8",
    )

    validator.validate_acl(acl)


@pytest.mark.parametrize(
    "pattern",
    [
        "api/trust/cert/delete/*",
        "api/trust/cert/generate_file/*/p12",
        "api/trust/*",
    ],
)
def test_acl_rejects_broad_or_private_routes(tmp_path: Path, pattern: str) -> None:
    acl = tmp_path / "ACL.xml"
    patterns = list(copy.copy(validator.EXPECTED_ACL_PATTERNS))
    patterns.append(pattern)
    acl.write_text(
        "<acl><rule><patterns>"
        + "".join(f"<pattern>{item}</pattern>" for item in patterns)
        + "</patterns></rule></acl>",
        encoding="utf-8",
    )

    with pytest.raises(validator.DeploymentValidationError):
        validator.validate_acl(acl)


def test_acl_rejects_declarations(tmp_path: Path) -> None:
    acl = tmp_path / "ACL.xml"
    acl.write_text(
        '<!DOCTYPE acl [<!ENTITY route "api/trust/cert/add">]>'
        "<acl><rule><patterns><pattern>&route;</pattern></patterns></rule></acl>",
        encoding="utf-8",
    )

    with pytest.raises(validator.DeploymentValidationError):
        validator.validate_acl(acl)
