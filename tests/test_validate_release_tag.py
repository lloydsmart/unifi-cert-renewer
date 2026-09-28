from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
validator = importlib.import_module("validate_release_tag")

TAG = "v0.1.0-rc.1"
TAG_OBJECT_SHA = "a" * 40
COMMIT_SHA = "b" * 40


def valid_ref(tag: str = TAG) -> dict[str, object]:
    return {
        "ref": f"refs/tags/{tag}",
        "object": {"type": "tag", "sha": TAG_OBJECT_SHA},
    }


def valid_tag(tag: str = TAG) -> dict[str, object]:
    return {
        "tag": tag,
        "sha": TAG_OBJECT_SHA,
        "object": {"type": "commit", "sha": COMMIT_SHA},
        "verification": {"verified": True, "reason": "valid"},
    }


@pytest.mark.parametrize(
    ("tag", "prerelease"),
    [
        ("v0.2.0", False),
        ("v0.2.0-beta.1", True),
        ("v0.2.0-rc.1", True),
        ("v12.34.56", False),
        ("v12.34.56-beta.789", True),
        ("v12.34.56-rc.789", True),
    ],
)
def test_validate_release_version_accepts_supported_syntax(
    tag: str, prerelease: bool
) -> None:
    assert validator.validate_release_version(tag) is prerelease


@pytest.mark.parametrize(("length", "accepted"), [(256, True), (257, False)])
@pytest.mark.parametrize(
    ("suffix", "prerelease"),
    [("", False), ("-beta.1", True), ("-rc.1", True)],
)
def test_release_tag_length_boundary(
    length: int, accepted: bool, suffix: str, prerelease: bool
) -> None:
    tail = f".2.3{suffix}"
    tag = "v" + "1" * (length - 1 - len(tail)) + tail
    assert len(tag) == length
    if accepted:
        assert validator.validate_release_version(tag) is prerelease
    else:
        with pytest.raises(
            validator.ReleaseTagValidationError, match="exceeds 256 characters"
        ):
            validator.validate_release_version(tag)


@pytest.mark.parametrize(
    ("tag", "output"),
    [
        ("v0.2.0", "false"),
        ("v0.2.0-beta.1", "true"),
        ("v0.2.0-rc.1", "true"),
    ],
)
def test_cli_version_reports_prerelease_state(
    tag: str, output: str, capsys: pytest.CaptureFixture[str]
) -> None:
    assert validator.main(["version", tag]) == 0
    assert capsys.readouterr().out == f"{output}\n"


@pytest.mark.parametrize(
    "tag",
    [
        "0.1.0",
        "v0.1",
        "v0.2.0-beta",
        "v0.2.0-beta.0",
        "v0.2.0-beta.01",
        "v0.2.0-rc",
        "v0.2.0-rc.0",
        "v0.2.0-rc.01",
        "v0.2.0-alpha.1",
        "v0.2.0-preview.1",
        "v0.2.0-beta.1+build",
        "v0.2.0-beta.1-rc.1",
        "v0.2.0-rc.1-beta.1",
        "v0.2.0-beta.1-beta.2",
        "v0.2.0-rc.1-rc.2",
        "v0.2.0-beta.1\n",
        "v0.2.0-beta.1 ",
        " v0.2.0-beta.1",
        "v0.2.0-beta.١",
        "v０.2.0-beta.1",
        "v0.2.0-βeta.1",
        "v0.2.0+build",
        "v01.2.0",
        "v0.02.0",
        "v0.2.00",
        "v0.1.0/other",
        "xv0.2.0",
        "v0.2.0extra",
    ],
)
def test_validate_release_version_rejects_malformed_versions(tag: str) -> None:
    with pytest.raises(validator.ReleaseTagValidationError):
        validator.validate_release_version(tag)


@pytest.mark.parametrize("tag", [TAG, "v0.2.0-beta.1"])
def test_validate_tag_ref_returns_annotated_tag_object_sha(tag: str) -> None:
    assert validator.validate_tag_ref(valid_ref(tag), tag) == TAG_OBJECT_SHA


def test_validate_tag_ref_rejects_lightweight_tag() -> None:
    document = valid_ref()
    document["object"] = {"type": "commit", "sha": COMMIT_SHA}
    with pytest.raises(validator.ReleaseTagValidationError):
        validator.validate_tag_ref(document, TAG)


@pytest.mark.parametrize("tag", [TAG, "v0.2.0-beta.1"])
def test_validate_tag_object_returns_target_commit(tag: str) -> None:
    assert (
        validator.validate_tag_object(valid_tag(tag), tag, TAG_OBJECT_SHA) == COMMIT_SHA
    )


@pytest.mark.parametrize(
    "verification",
    [
        {"verified": False, "reason": "unsigned"},
        {"verified": False, "reason": "unknown_key"},
        {"verified": True, "reason": "expired_key"},
    ],
)
def test_validate_tag_object_rejects_unverified_or_nonvalid_verification(
    verification: dict[str, object],
) -> None:
    document = valid_tag()
    document["verification"] = verification
    with pytest.raises(validator.ReleaseTagValidationError):
        validator.validate_tag_object(document, TAG, TAG_OBJECT_SHA)


def test_validate_tag_object_rejects_noncommit_target() -> None:
    document = valid_tag()
    document["object"] = {"type": "tree", "sha": COMMIT_SHA}
    with pytest.raises(validator.ReleaseTagValidationError):
        validator.validate_tag_object(document, TAG, TAG_OBJECT_SHA)


def test_validate_tag_object_rejects_mismatched_tag_name() -> None:
    document = valid_tag()
    document["tag"] = "v0.1.0"
    with pytest.raises(validator.ReleaseTagValidationError):
        validator.validate_tag_object(document, TAG, TAG_OBJECT_SHA)


def test_validate_tag_object_rejects_mismatched_object_sha() -> None:
    document = valid_tag()
    document["sha"] = "c" * 40
    with pytest.raises(validator.ReleaseTagValidationError):
        validator.validate_tag_object(document, TAG, TAG_OBJECT_SHA)


@pytest.mark.parametrize("tag", [TAG, "v0.2.0-beta.1"])
def test_cli_validates_synthetic_github_responses(
    tag: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    ref_path = tmp_path / "ref.json"
    tag_path = tmp_path / "tag.json"
    ref_path.write_text(json.dumps(valid_ref(tag)), encoding="utf-8")
    tag_path.write_text(json.dumps(valid_tag(tag)), encoding="utf-8")

    assert validator.main(["ref", tag, str(ref_path)]) == 0
    assert capsys.readouterr().out == f"{TAG_OBJECT_SHA}\n"
    assert validator.main(["tag", tag, TAG_OBJECT_SHA, str(tag_path)]) == 0
    assert capsys.readouterr().out == f"{COMMIT_SHA}\n"
