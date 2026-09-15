from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "publish-release-image.sh"
TESTED_ID = "sha256:" + "a" * 64
DIFFERENT_ID = "sha256:" + "b" * 64
PUSHED_DIGEST = "sha256:" + "c" * 64
EXISTING_DIGEST = "sha256:" + "d" * 64
REPOSITORY = "ghcr.io/lloydsmart/unifi-cert-renewer"
RELEASE_TAG = "v0.1.0-rc.1"
RELEASE_REF = f"{REPOSITORY}:{RELEASE_TAG}"

FAKE_DOCKER = r"""#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$FAKE_DOCKER_LOG"

if [[ $1 == manifest && $2 == inspect ]]; then
    case "$FAKE_REGISTRY_CASE" in
        absent)
            printf '%s\n' 'manifest unknown' >&2
            exit 1
            ;;
        error)
            printf '%s\n' 'unauthorized: registry access failed' >&2
            exit 1
            ;;
        mixed)
            printf '%s\n' 'manifest unknown' 'unauthorized: registry access failed' >&2
            exit 1
            ;;
        *)
            exit 0
            ;;
    esac
fi

if [[ $1 == image && $2 == inspect && $3 == --format ]]; then
    format=$4
    reference=$5
    if [[ $format == '{{.Id}}' ]]; then
        if [[ $reference == "$RELEASE_REF" && $FAKE_REGISTRY_CASE == different ]]; then
            printf '%s\n' "$DIFFERENT_ID"
        else
            printf '%s\n' "$TESTED_ID"
        fi
        exit 0
    fi
    if [[ $format == '{{range .RepoDigests}}{{println .}}{{end}}' ]]; then
        printf '%s@%s\n' "$REPOSITORY" "$EXISTING_DIGEST"
        exit 0
    fi
fi

if [[ $1 == tag ]]; then
    exit 0
fi
if [[ $1 == push ]]; then
    printf 'release: digest: %s size: 1234\n' "$PUSHED_DIGEST"
    exit 0
fi
if [[ $1 == pull ]]; then
    exit 0
fi

printf 'Unexpected fake docker invocation: %s\n' "$*" >&2
exit 99
"""


@pytest.fixture
def fake_registry(tmp_path: Path) -> tuple[dict[str, str], Path]:
    binary_directory = tmp_path / "bin"
    binary_directory.mkdir()
    docker = binary_directory / "docker"
    docker.write_text(FAKE_DOCKER, encoding="utf-8")
    docker.chmod(0o755)
    log = tmp_path / "docker.log"
    environment = os.environ.copy()
    environment.update(
        {
            "PATH": f"{binary_directory}:{environment['PATH']}",
            "TMPDIR": str(tmp_path),
            "FAKE_DOCKER_LOG": str(log),
            "TESTED_ID": TESTED_ID,
            "DIFFERENT_ID": DIFFERENT_ID,
            "PUSHED_DIGEST": PUSHED_DIGEST,
            "EXISTING_DIGEST": EXISTING_DIGEST,
            "REPOSITORY": REPOSITORY,
            "RELEASE_REF": RELEASE_REF,
        }
    )
    return environment, log


def run_helper(
    environment: dict[str, str], registry_case: str
) -> subprocess.CompletedProcess[str]:
    environment["FAKE_REGISTRY_CASE"] = registry_case
    return subprocess.run(
        [str(SCRIPT), TESTED_ID, REPOSITORY, RELEASE_TAG],
        check=False,
        capture_output=True,
        encoding="utf-8",
        env=environment,
    )


def test_absent_tag_publishes_and_verifies_digest(
    fake_registry: tuple[dict[str, str], Path],
) -> None:
    environment, log = fake_registry
    result = run_helper(environment, "absent")

    assert result.returncode == 0
    assert result.stdout == PUSHED_DIGEST
    calls = log.read_text(encoding="utf-8").splitlines()
    assert f"tag {TESTED_ID} {RELEASE_REF}" in calls
    assert f"push {RELEASE_REF}" in calls
    assert f"pull {REPOSITORY}@{PUSHED_DIGEST}" in calls


def test_identical_existing_tag_reuses_digest_without_push(
    fake_registry: tuple[dict[str, str], Path],
) -> None:
    environment, log = fake_registry
    result = run_helper(environment, "identical")

    assert result.returncode == 0
    assert result.stdout == EXISTING_DIGEST
    calls = log.read_text(encoding="utf-8").splitlines()
    assert f"pull {RELEASE_REF}" in calls
    assert f"pull {REPOSITORY}@{EXISTING_DIGEST}" in calls
    assert not any(call.startswith(("tag ", "push ")) for call in calls)


def test_different_existing_tag_fails_without_overwrite(
    fake_registry: tuple[dict[str, str], Path],
) -> None:
    environment, log = fake_registry
    result = run_helper(environment, "different")

    assert result.returncode == 1
    assert "refers to different content" in result.stderr
    calls = log.read_text(encoding="utf-8").splitlines()
    assert f"pull {RELEASE_REF}" in calls
    assert not any(call.startswith(("tag ", "push ")) for call in calls)


def test_registry_error_fails_closed_without_publication(
    fake_registry: tuple[dict[str, str], Path],
) -> None:
    environment, log = fake_registry
    result = run_helper(environment, "error")

    assert result.returncode == 1
    assert "Could not determine whether release image tag exists" in result.stderr
    calls = log.read_text(encoding="utf-8").splitlines()
    assert not any(call.startswith(("tag ", "push ", "pull ")) for call in calls)


def test_manifest_not_found_mixed_with_registry_error_fails_closed(
    fake_registry: tuple[dict[str, str], Path],
) -> None:
    environment, log = fake_registry
    result = run_helper(environment, "mixed")

    assert result.returncode == 1
    assert "Could not determine whether release image tag exists" in result.stderr
    calls = log.read_text(encoding="utf-8").splitlines()
    assert not any(call.startswith(("tag ", "push ", "pull ")) for call in calls)
