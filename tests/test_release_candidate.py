from __future__ import annotations

import hashlib
import importlib
import json
import os
import re
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
candidate = importlib.import_module("release_candidate")
validator = importlib.import_module("validate_release_tag")
WORKFLOW = ROOT / ".github/workflows/release.yml"


def boundary_tag(length: int, suffix: str) -> str:
    tail = f".2.3{suffix}"
    tag = "v" + "1" * (length - 1 - len(tail)) + tail
    assert len(tag) == length
    return tag


BOUNDARY_TAGS = tuple(
    (boundary_tag(128, suffix), boundary_tag(129, suffix))
    for suffix in ("", "-beta.1", "-rc.1")
)
VALID_RELEASE_TAGS = (
    "v0.0.0",
    "v1.2.3",
    "v1.2.3-beta.1",
    "v12.34.56-beta.789",
    "v1.2.3-rc.1",
    "v12.34.56-rc.789",
    *(accepted for accepted, _ in BOUNDARY_TAGS),
)
INVALID_RELEASE_TAGS = (
    "v1.2.3-beta",
    "v1.2.3-beta.0",
    "v1.2.3-beta.01",
    "v1.2.3-rc",
    "v1.2.3-rc.0",
    "v1.2.3-rc.01",
    "v1.2.3-alpha.1",
    "v1.2.3-preview.1",
    "v1.2.3-beta.1+build",
    "v1.2.3+build",
    "v1.2.3-beta.1-rc.1",
    "v1.2.3-rc.1-beta.1",
    "v1.2.3-beta.1-beta.2",
    "v1.2.3-rc.1-rc.2",
    "v1.2.3-beta.1\n",
    "v1.2.3-beta.1 ",
    " v1.2.3-beta.1",
    "v1.2.3-beta.١",
    "v１.2.3-beta.1",
    "v1.2.3-βeta.1",
    "v01.2.3",
    "v1.02.3",
    "v1.2.03",
    "xv1.2.3",
    "v1.2.3extra",
    *(rejected for _, rejected in BOUNDARY_TAGS),
)


def workflow_step(name: str) -> str:
    section = WORKFLOW.read_text().split(f"      - name: {name}\n", 1)[1]
    section = section.split("\n      - name:", 1)[0]
    return textwrap.dedent(section.split("        run: |\n", 1)[1])


@pytest.fixture
def handoff(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    values = {
        "GITHUB_REPOSITORY": "lloydsmart/unifi-cert-renewer",
        "SOURCE_SHA": "a" * 40,
        "RELEASE_TAG": "v1.2.3-rc.1",
        "GITHUB_RUN_ID": "1234",
        "GITHUB_RUN_ATTEMPT": "2",
        "RENEWER_ID": "sha256:" + "b" * 64,
        "UNIFI_ID": "sha256:" + "c" * 64,
        "RUNNER_TEMP": str(tmp_path),
    }
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    directory = tmp_path / "release-candidate"
    directory.mkdir()
    for name in candidate.FILES:
        contents = b"synthetic image archive " + name.encode()
        if name.endswith(".json"):
            contents = b'{"spdxVersion":"SPDX-2.3","packages":[]}'
        (directory / name).write_bytes(contents)
    monkeypatch.setenv("MANIFEST_SHA256", candidate.create(directory))
    return directory


def rewrite_manifest(
    directory: Path, monkeypatch: pytest.MonkeyPatch, document
) -> None:
    contents = json.dumps(document).encode()
    (directory / candidate.MANIFEST).write_bytes(contents)
    monkeypatch.setenv("MANIFEST_SHA256", hashlib.sha256(contents).hexdigest())


def test_valid_candidate(handoff: Path) -> None:
    assert candidate.verify(handoff) == {
        "renewer": os.environ["RENEWER_ID"],
        "unifi": os.environ["UNIFI_ID"],
    }


@pytest.mark.parametrize("tag", VALID_RELEASE_TAGS)
def test_release_tag_candidate_lifecycle_in_isolated_mode(
    handoff: Path, monkeypatch: pytest.MonkeyPatch, tag: str
) -> None:
    manifest = handoff / candidate.MANIFEST
    manifest.unlink()
    monkeypatch.setenv("RELEASE_TAG", tag)
    command = [sys.executable, "-I", str(ROOT / "scripts/release_candidate.py")]

    created = subprocess.run(
        [*command, "create", str(handoff)],
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert created.returncode == 0, created.stderr
    digest = re.fullmatch(r"manifest_sha256=([0-9a-f]{64})\n", created.stdout)
    assert digest is not None
    monkeypatch.setenv("MANIFEST_SHA256", digest.group(1))
    assert json.loads(manifest.read_text(encoding="utf-8"))["release_tag"] == tag

    verified = subprocess.run(
        [*command, "verify", str(handoff)],
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert verified.returncode == 0, verified.stderr


@pytest.mark.parametrize(("accepted", "rejected"), BOUNDARY_TAGS)
def test_release_tag_length_boundary_in_candidate(
    handoff: Path, monkeypatch: pytest.MonkeyPatch, accepted: str, rejected: str
) -> None:
    assert len(accepted) == 128
    assert len(rejected) == 129
    manifest = handoff / candidate.MANIFEST
    manifest.unlink()
    monkeypatch.setenv("RELEASE_TAG", accepted)
    monkeypatch.setenv("MANIFEST_SHA256", candidate.create(handoff))
    assert json.loads(manifest.read_text(encoding="utf-8"))["release_tag"] == accepted
    assert candidate.verify(handoff)["renewer"] == os.environ["RENEWER_ID"]

    monkeypatch.setenv("RELEASE_TAG", rejected)
    with pytest.raises(
        candidate.CandidateError, match="invalid expected workflow identity"
    ):
        candidate.verify(handoff)


@pytest.mark.parametrize("tag", INVALID_RELEASE_TAGS)
def test_malformed_release_tag_rejected_by_candidate_create_and_verify(
    handoff: Path, monkeypatch: pytest.MonkeyPatch, tag: str
) -> None:
    monkeypatch.setenv("RELEASE_TAG", tag)
    with pytest.raises(
        candidate.CandidateError, match="invalid expected workflow identity"
    ):
        candidate.verify(handoff)

    manifest = handoff / candidate.MANIFEST
    manifest.unlink()
    with pytest.raises(
        candidate.CandidateError, match="invalid expected workflow identity"
    ):
        candidate.create(handoff)
    assert not manifest.exists()


@pytest.mark.parametrize(
    ("tag", "expected"),
    [(tag, True) for tag in VALID_RELEASE_TAGS]
    + [(tag, False) for tag in INVALID_RELEASE_TAGS],
)
def test_release_and_candidate_tag_validators_agree(
    handoff: Path, monkeypatch: pytest.MonkeyPatch, tag: str, expected: bool
) -> None:
    monkeypatch.setenv("RELEASE_TAG", tag)
    try:
        validator.validate_release_version(tag)
    except validator.ReleaseTagValidationError:
        release_accepts = False
    else:
        release_accepts = True

    try:
        candidate.context()
    except candidate.CandidateError:
        candidate_accepts = False
    else:
        candidate_accepts = True

    assert release_accepts == candidate_accepts == expected


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("GITHUB_REPOSITORY", "elsewhere/repository"),
        ("SOURCE_SHA", "d" * 40),
        ("RELEASE_TAG", "v1.2.3"),
        ("GITHUB_RUN_ID", "5678"),
        ("GITHUB_RUN_ATTEMPT", "3"),
        ("RENEWER_ID", "sha256:" + "d" * 64),
        ("UNIFI_ID", "sha256:" + "d" * 64),
        ("RENEWER_ID", "sha256:" + "c" * 64),
        ("MANIFEST_SHA256", "0" * 64),
        ("MANIFEST_SHA256", "0" * 64 + "\n"),
        ("RELEASE_TAG", "v1.2.3\nevil"),
        ("SOURCE_SHA", "HEAD"),
        ("GITHUB_RUN_ATTEMPT", "0"),
        ("RENEWER_ID", "$(touch /tmp/unsafe)"),
    ],
)
def test_mismatched_context_rejected(handoff, monkeypatch, key, value) -> None:
    monkeypatch.setenv(key, value)
    with pytest.raises(candidate.CandidateError):
        candidate.verify(handoff)


@pytest.mark.parametrize("filename", candidate.FILES)
@pytest.mark.parametrize(
    "change", ["missing", "corrupt", "empty", "symlink", "hardlink"]
)
def test_changed_file_rejected(handoff, filename, change) -> None:
    path = handoff / filename
    original = path.read_bytes()
    path.unlink()
    if change == "corrupt":
        path.write_bytes(original + b"corruption")
    elif change == "empty":
        path.touch()
    elif change in ("symlink", "hardlink"):
        target = handoff.parent / "outside"
        target.write_bytes(original)
        if change == "symlink":
            path.symlink_to(target)
        else:
            path.hardlink_to(target)
    with pytest.raises((candidate.CandidateError, OSError, ValueError)):
        candidate.verify(handoff)


@pytest.mark.parametrize(
    "entry", ["evil.sh", "../not-allowed", ".hidden", "subdirectory"]
)
def test_unexpected_manifest_path_rejected(handoff, monkeypatch, entry) -> None:
    document = json.loads((handoff / candidate.MANIFEST).read_bytes())
    document["files"][entry] = "0" * 64
    rewrite_manifest(handoff, monkeypatch, document)
    with pytest.raises(candidate.CandidateError):
        candidate.verify(handoff)


@pytest.mark.parametrize("value", [True, 2, "1", None])
def test_schema_rejected(handoff, monkeypatch, value) -> None:
    document = json.loads((handoff / candidate.MANIFEST).read_bytes())
    document["schema_version"] = value
    rewrite_manifest(handoff, monkeypatch, document)
    with pytest.raises(candidate.CandidateError):
        candidate.verify(handoff)


def test_duplicate_manifest_key_rejected(handoff, monkeypatch) -> None:
    path = handoff / candidate.MANIFEST
    contents = path.read_bytes().replace(
        b'"schema_version": 1', b'"schema_version": 1, "schema_version": 1'
    )
    path.write_bytes(contents)
    monkeypatch.setenv("MANIFEST_SHA256", hashlib.sha256(contents).hexdigest())
    with pytest.raises(candidate.CandidateError):
        candidate.verify(handoff)


@pytest.mark.parametrize("change", ["extra", "fifo", "directory-link", "oversized"])
def test_unsafe_inventory_rejected(handoff, monkeypatch, change) -> None:
    if change == "extra":
        (handoff / "injected.py").write_text("raise SystemExit(0)")
    elif change == "fifo":
        (handoff / "renewer.tar").unlink()
        os.mkfifo(handoff / "renewer.tar")
    elif change == "directory-link":
        link = handoff.parent / "link"
        link.symlink_to(handoff, target_is_directory=True)
        handoff = link
    elif change == "oversized":
        monkeypatch.setitem(candidate.FILES, "renewer.tar", 4)
    with pytest.raises(candidate.CandidateError):
        candidate.verify(handoff)


FAKE_DOCKER = r"""#!/usr/bin/env python3
import os
import sys
from pathlib import Path
args = sys.argv[1:]
with open(os.environ['DOCKER_LOG'], 'a') as log:
    log.write(' '.join(args) + '\n')
if args[0] == 'load':
    sys.exit(0)
if args[:3] != ['image', 'inspect', '--format']:
    sys.exit(99)
expression, image_id = args[3:]
values = {
    '{{.Id}}': image_id,
    '{{ index .Config.Labels "org.opencontainers.image.source" }}': 'https://github.com/' + os.environ['GITHUB_REPOSITORY'],
    '{{ index .Config.Labels "org.opencontainers.image.revision" }}': os.environ['SOURCE_SHA'],
    '{{ index .Config.Labels "org.opencontainers.image.version" }}': os.environ['RELEASE_TAG'],
    '{{ index .Config.Labels "net.unraid.docker.icon" }}': 'https://raw.githubusercontent.com/' + os.environ['GITHUB_REPOSITORY'] + '/' + os.environ['SOURCE_SHA'] + '/assets/icon.png',
}
value = values[expression]
if os.environ.get('BAD_INSPECT') in ('id' if expression == '{{.Id}}' else expression, 'all'):
    value = 'wrong'
print(value)
"""


@pytest.mark.parametrize(
    "damage",
    ["none", "archive", "sbom", "id", "source", "revision", "version", "icon", "extra"],
)
def test_actual_handoff_step_rejects_before_authentication(
    handoff, monkeypatch, damage
) -> None:
    binary = handoff.parent / "bin"
    binary.mkdir()
    docker = binary / "docker"
    docker.write_text(FAKE_DOCKER)
    docker.chmod(0o755)
    log = handoff.parent / "docker.log"
    marker = handoff.parent / "authenticated"
    monkeypatch.setenv("PATH", str(binary) + os.pathsep + os.environ["PATH"])
    monkeypatch.setenv("DOCKER_LOG", str(log))
    if damage in ("archive", "sbom"):
        name = "renewer.tar" if damage == "archive" else "unifi-cert-renewer.spdx.json"
        (handoff / name).write_bytes(b"corrupted")
    elif damage == "extra":
        (handoff / "attack.sh").write_text("touch /tmp/should-never-run")
    elif damage == "id":
        monkeypatch.setenv("BAD_INSPECT", "id")
    elif damage in ("source", "revision", "version", "icon"):
        label = f"org.opencontainers.image.{damage}"
        if damage == "icon":
            label = "net.unraid.docker.icon"
        monkeypatch.setenv("BAD_INSPECT", '{{ index .Config.Labels "' + label + '" }}')
    script = workflow_step("Verify handoff before loading images or authenticating")
    script += '\nprintf done >"$RUNNER_TEMP/authenticated"\n'
    result = subprocess.run(
        ["bash", "-c", script], cwd=ROOT, capture_output=True, timeout=20
    )
    assert (result.returncode == 0) == (damage == "none"), result.stderr
    assert marker.exists() == (damage == "none")
    calls = log.read_text() if log.exists() else ""
    assert "run " not in calls
    assert "login" not in calls
    if damage in ("archive", "sbom", "extra"):
        assert not calls
    if damage == "none":
        assert calls.count("load --input") == 2
        assert (handoff.parent / "release-sboms/unifi-cert-renewer.spdx.json").is_file()


def test_release_workflow_keeps_build_execution_read_only() -> None:
    workflow = WORKFLOW.read_text()
    verify = workflow.split("\n  verify:\n", 1)[1].split("\n  publish:\n", 1)[0]
    publish = workflow.split("\n  publish:\n", 1)[1].split("\n  release:\n", 1)[0]
    release = workflow.split("\n  release:\n", 1)[1]
    assert "permissions:\n      contents: read\n    outputs:" in verify
    assert ": write" not in verify
    assert "docker build" in verify and "scan-container.sh" in verify
    assert "needs: [verify, qualification]" in publish and "needs: publish" in release
    assert "ref: ${{ github.sha }}" in publish
    assert "persist-credentials: false" in publish
    assert "artifact-ids: ${{ needs.verify.outputs.artifact_id }}" in publish
    assert "digest-mismatch: error" in publish
    assert "github-token:" not in publish and "run-id:" not in publish
    assert (
        re.search(r"docker (build|run|exec)|pip install|pytest|scan-container", publish)
        is None
    )
    assert publish.index("release_candidate.py verify") < publish.index("docker load")
    assert publish.index("docker load") < publish.index("docker login")
    assert "needs.verify.outputs" not in release
    assert "sbom_artifact_id: ${{ steps.sboms.outputs.artifact-id }}" in publish
    assert "artifact-ids: ${{ needs.publish.outputs.sbom_artifact_id }}" in release
    assert "digest-mismatch: error" in release
    assert "github-token:" not in release and "run-id:" not in release
    assert "contents: write" in release and "packages: write" not in release


@pytest.mark.parametrize(
    "contents",
    [b"[]", b"null", b"\xff", b'{"spdxVersion":"SPDX-2.2"}', b'{"x":NaN}'],
)
def test_invalid_sbom_rejected_even_with_matching_checksum(
    handoff, monkeypatch, contents
) -> None:
    filename = "unifi-cert-renewer.spdx.json"
    (handoff / filename).write_bytes(contents)
    document = json.loads((handoff / candidate.MANIFEST).read_bytes())
    document["files"][filename] = hashlib.sha256(contents).hexdigest()
    rewrite_manifest(handoff, monkeypatch, document)
    with pytest.raises((ValueError, UnicodeError)):
        candidate.verify(handoff)
