#!/usr/bin/env python3
"""Bind fixed release artifacts to one verified source and workflow attempt."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any

FILES = {
    "renewer.tar": 16 * 1024**3,
    "unifi.tar": 16 * 1024**3,
    "unifi-cert-renewer.spdx.json": 16 * 1024**2,
    "unifi-network-application-cert-renewer.spdx.json": 16 * 1024**2,
}
MANIFEST = "candidate.json"
MANIFEST_LIMIT = 16384
SHA256 = re.compile(r"[0-9a-f]{64}")
IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")
TAG = re.compile(
    r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-rc\.[1-9][0-9]*)?"
)


class CandidateError(ValueError):
    """The candidate is missing, malformed, or belongs to another build."""


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CandidateError("duplicate JSON key")
        result[key] = value
    return result


def read_file(path: Path, limit: int) -> tuple[str, bytes]:
    """Hash bounded regular files without following links; retain only JSON."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise CandidateError("candidate entries must be regular unlinked files")
        if not 0 < info.st_size <= limit:
            raise CandidateError("candidate file has invalid size")
        digest = hashlib.sha256()
        contents = bytearray()
        size = 0
        while chunk := stream.read(1024 * 1024):
            size += len(chunk)
            if size > limit:
                raise CandidateError("candidate file exceeds size limit")
            digest.update(chunk)
            if path.suffix == ".json":
                contents.extend(chunk)
        after = os.fstat(stream.fileno())
        fields = (
            "st_dev",
            "st_ino",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
            "st_nlink",
        )
        if size != info.st_size or any(
            getattr(info, field) != getattr(after, field) for field in fields
        ):
            raise CandidateError("candidate file changed during validation")
    return digest.hexdigest(), bytes(contents)


def reject_constant(value: str) -> None:
    raise CandidateError("non-JSON numeric constant")


def json_object(contents: bytes) -> dict[str, Any]:
    document = json.loads(
        contents.decode("utf-8"),
        object_pairs_hook=unique_object,
        parse_constant=reject_constant,
    )
    if not isinstance(document, dict):
        raise CandidateError("JSON must be an object")
    return document


def context() -> dict[str, str]:
    expected = {
        "repository": os.environ["GITHUB_REPOSITORY"],
        "source_sha": os.environ["SOURCE_SHA"],
        "release_tag": os.environ["RELEASE_TAG"],
        "run_id": os.environ["GITHUB_RUN_ID"],
        "run_attempt": os.environ["GITHUB_RUN_ATTEMPT"],
    }
    patterns = {
        "repository": r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+",
        "source_sha": r"[0-9a-f]{40}",
        "release_tag": TAG.pattern,
        "run_id": r"[1-9][0-9]*",
        "run_attempt": r"[1-9][0-9]*",
    }
    if any(
        len(value) > 256 or re.fullmatch(patterns[key], value) is None
        for key, value in expected.items()
    ):
        raise CandidateError("invalid expected workflow identity")
    return expected


def image_ids() -> dict[str, str]:
    ids = {name: os.environ[f"{name.upper()}_ID"] for name in ("renewer", "unifi")}
    if any(IMAGE_ID.fullmatch(value) is None for value in ids.values()):
        raise CandidateError("invalid tested image identity")
    if ids["renewer"] == ids["unifi"]:
        raise CandidateError("release images must have distinct identities")
    return ids


def inventory(directory: Path, *, with_manifest: bool) -> dict[str, str]:
    if not stat.S_ISDIR(directory.lstat().st_mode):
        raise CandidateError("candidate directory must not be a link")
    expected = set(FILES) | ({MANIFEST} if with_manifest else set())
    if {entry.name for entry in directory.iterdir()} != expected:
        raise CandidateError("candidate file inventory differs from the fixed contract")
    digests = {}
    for name, limit in FILES.items():
        digest, contents = read_file(directory / name, limit)
        digests[name] = digest
        if name.endswith(".json"):
            sbom = json_object(contents)
            if sbom.get("spdxVersion") != "SPDX-2.3":
                raise CandidateError("candidate SBOM must be SPDX 2.3")
    return digests


def create(directory: Path) -> str:
    expected = context()
    ids = image_ids()
    digests = inventory(directory, with_manifest=False)
    document = {"schema_version": 1, **expected, "image_ids": ids, "files": digests}
    contents = (json.dumps(document, sort_keys=True, indent=2) + "\n").encode("utf-8")
    with (directory / MANIFEST).open("xb") as output:
        output.write(contents)
    return hashlib.sha256(contents).hexdigest()


def verify(directory: Path) -> dict[str, str]:
    expected = context()
    ids = image_ids()
    manifest_digest = os.environ["MANIFEST_SHA256"]
    if SHA256.fullmatch(manifest_digest) is None:
        raise CandidateError("invalid manifest digest")
    if not stat.S_ISDIR(directory.lstat().st_mode):
        raise CandidateError("candidate directory must not be a link")
    digest, contents = read_file(directory / MANIFEST, MANIFEST_LIMIT)
    if digest != manifest_digest:
        raise CandidateError("candidate manifest digest mismatch")
    document = json_object(contents)
    if set(document) != {"schema_version", *expected, "image_ids", "files"}:
        raise CandidateError("unexpected manifest fields")
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise CandidateError("unsupported candidate schema")
    if any(document[key] != value for key, value in expected.items()):
        raise CandidateError("candidate belongs to another workflow identity")
    if document["image_ids"] != ids:
        raise CandidateError("candidate image identity mismatch")
    if document["files"] != inventory(directory, with_manifest=True):
        raise CandidateError("candidate file digest mismatch")
    return ids


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("create", "verify"))
    parser.add_argument("directory", type=Path)
    arguments = parser.parse_args()
    try:
        if arguments.mode == "create":
            print(f"manifest_sha256={create(arguments.directory)}")
        else:
            verify(arguments.directory)
    except (OSError, ValueError, KeyError, RecursionError) as error:
        print(f"Release candidate rejected: {type(error).__name__}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
