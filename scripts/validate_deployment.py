#!/usr/bin/env python3
"""Validate resolved deployment artifacts used by container CI."""

from __future__ import annotations

import argparse
import json
import sys
import xml.etree.ElementTree as ElementTree
from pathlib import Path
from typing import Any

MAX_INPUT_BYTES = 1024 * 1024
EXPECTED_ACL_PATTERNS = (
    "api/trust/cert/add",
    "api/trust/cert/ca_list",
    "api/trust/cert/generate_file/*/crt",
)
EXPECTED_TMPFS = "/tmp:rw,noexec,nosuid,nodev,size=16m"
EXPECTED_RENEWER_IMAGE = "local/unifi-cert-renewer:ci"
EXPECTED_NETWORK_NAME = "unifi-ci"
EXPECTED_SECRETS_DIRECTORY = "/tmp/unifi-cert-renewer-ci-secrets"


class DeploymentValidationError(ValueError):
    """Raised when a deployment artifact violates the expected boundary."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DeploymentValidationError("JSON contains a duplicate object key")
        result[key] = value
    return result


def _read_bounded(path: Path) -> bytes:
    try:
        size = path.stat().st_size
    except OSError as error:
        raise DeploymentValidationError("input is not readable") from error
    if size == 0:
        raise DeploymentValidationError("input is empty")
    if size > MAX_INPUT_BYTES:
        raise DeploymentValidationError("input exceeds the size limit")
    try:
        return path.read_bytes()
    except OSError as error:
        raise DeploymentValidationError("input is not readable") from error


def load_compose_json(path: Path) -> dict[str, Any]:
    try:
        document = json.loads(
            _read_bounded(path), object_pairs_hook=_reject_duplicate_keys
        )
    except (UnicodeError, json.JSONDecodeError) as error:
        raise DeploymentValidationError("Compose output is not valid JSON") from error
    if not isinstance(document, dict):
        raise DeploymentValidationError("Compose output must be a JSON object")
    return document


def _required_object(container: dict[str, Any], key: str) -> dict[str, Any]:
    value = container.get(key)
    if not isinstance(value, dict):
        raise DeploymentValidationError(f"Compose {key} must be an object")
    return value


def validate_compose(document: dict[str, Any]) -> None:
    services = _required_object(document, "services")
    if set(services) != {"renewer"}:
        raise DeploymentValidationError("Compose must define only the renewer service")
    renewer = services["renewer"]
    if not isinstance(renewer, dict):
        raise DeploymentValidationError("Compose renewer service must be an object")

    exact_values = {
        "image": EXPECTED_RENEWER_IMAGE,
        "user": "1000:1000",
        "group_add": ["984"],
        "read_only": True,
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
        "restart": "no",
        "pids_limit": 64,
        "tmpfs": [EXPECTED_TMPFS],
    }
    for key, expected in exact_values.items():
        if renewer.get(key) != expected:
            raise DeploymentValidationError(
                f"Compose renewer {key} does not match the hardened value"
            )

    volumes = renewer.get("volumes")
    if not isinstance(volumes, list) or len(volumes) != 2:
        raise DeploymentValidationError(
            "Compose renewer must have exactly two bind mounts"
        )
    expected_mounts = {
        ("/run/unifi-cert-renewer", "/run/unifi-cert-renewer"),
        (EXPECTED_SECRETS_DIRECTORY, "/run/secrets"),
    }
    actual_mounts: set[tuple[str, str]] = set()
    for volume in volumes:
        if not isinstance(volume, dict):
            raise DeploymentValidationError("Compose volume must be an object")
        if volume.get("type") != "bind" or volume.get("read_only") is not True:
            raise DeploymentValidationError(
                "Compose mounts must be read-only bind mounts"
            )
        source = volume.get("source")
        target = volume.get("target")
        if not isinstance(source, str) or not isinstance(target, str):
            raise DeploymentValidationError(
                "Compose mount source and target must be text"
            )
        actual_mounts.add((source, target))
    if actual_mounts != expected_mounts:
        raise DeploymentValidationError("Compose mount set is not the intended set")

    service_networks = renewer.get("networks")
    if not isinstance(service_networks, dict) or set(service_networks) != {"unifi"}:
        raise DeploymentValidationError(
            "Compose renewer must use only the shared UniFi network"
        )
    networks = _required_object(document, "networks")
    if set(networks) != {"unifi"}:
        raise DeploymentValidationError("Compose must define only the UniFi network")
    unifi_network = networks["unifi"]
    if not isinstance(unifi_network, dict):
        raise DeploymentValidationError("Compose UniFi network must be an object")
    if unifi_network.get("external") is not True:
        raise DeploymentValidationError("Compose UniFi network must be external")
    if unifi_network.get("name") != EXPECTED_NETWORK_NAME:
        raise DeploymentValidationError(
            "Compose UniFi network did not resolve the CI network name"
        )


def validate_acl(path: Path) -> None:
    raw_xml = _read_bounded(path)
    if b"<!DOCTYPE" in raw_xml.upper() or b"<!ENTITY" in raw_xml.upper():
        raise DeploymentValidationError("ACL XML must not contain declarations")
    try:
        root = ElementTree.fromstring(raw_xml)
    except ElementTree.ParseError as error:
        raise DeploymentValidationError("ACL is not valid XML") from error
    if root.tag != "acl":
        raise DeploymentValidationError("ACL root element must be acl")

    patterns = tuple(
        element.text.strip()
        for element in root.findall("./*/patterns/pattern")
        if element.text is not None
    )
    if patterns != EXPECTED_ACL_PATTERNS:
        raise DeploymentValidationError(
            "ACL patterns do not match the exact certificate-renewer route set"
        )
    if len(root.findall(".//pattern")) != len(EXPECTED_ACL_PATTERNS):
        raise DeploymentValidationError(
            "ACL contains patterns outside the expected rule"
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="artifact", required=True)
    compose_parser = subparsers.add_parser("compose")
    compose_parser.add_argument("path", type=Path)
    acl_parser = subparsers.add_parser("acl")
    acl_parser.add_argument("path", type=Path)
    arguments = parser.parse_args(argv)

    try:
        if arguments.artifact == "compose":
            validate_compose(load_compose_json(arguments.path))
        else:
            validate_acl(arguments.path)
    except DeploymentValidationError as error:
        print(f"Deployment validation failed: {error}", file=sys.stderr)
        return 1

    print(f"Validated {arguments.artifact} deployment boundary")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
