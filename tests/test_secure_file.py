import os
import stat
from types import SimpleNamespace

import pytest

import secure_file


@pytest.fixture(autouse=True)
def trusted_root(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(secure_file, "SECURE_FILE_ROOT", str(tmp_path))


def test_accepts_regular_file_owned_by_effective_user(tmp_path) -> None:
    path = tmp_path / "credential"
    path.write_bytes(b"secret")
    path.chmod(0o600)

    with secure_file.open_secure_file(path.name, source_name="Credential") as file:
        assert file.read() == b"secret"


def test_safe_basename_resolves_beneath_normalized_trusted_root(tmp_path) -> None:
    assert secure_file._resolve_secure_path("credential.pem", "Credential") == (
        str(tmp_path),
        str(tmp_path / "credential.pem"),
        "credential.pem",
    )


@pytest.mark.parametrize(
    "filename",
    [
        "/etc/passwd",
        "../outside",
        "prefix/../outside",
        "nested/name",
        "nested\\name",
        ".",
        "..",
        "",
        "unsafe\x00name",
        "unsafe\nname",
        "unsafe\u202ename",
        "unsafe\u2028name",
        "unsafe\ud800name",
        "unsafe name",
        "caf\N{LATIN SMALL LETTER E WITH ACUTE}",
        "a" * (secure_file.MAX_SECURE_FILENAME_CHARS + 1),
    ],
)
def test_rejects_unsafe_or_outside_filename_before_filesystem_access(
    monkeypatch, filename
) -> None:
    filesystem_calls: list[str] = []
    monkeypatch.setattr(
        secure_file.os,
        "lstat",
        lambda path: filesystem_calls.append(path),
    )
    monkeypatch.setattr(
        secure_file.os,
        "open",
        lambda path, flags: filesystem_calls.append(path),
    )

    with pytest.raises(secure_file.SecureFileError, match="filename") as raised:
        secure_file.open_secure_file(filename, source_name="Credential")

    assert filesystem_calls == []
    if filename:
        assert filename not in str(raised.value)


def test_rejects_non_text_filename() -> None:
    with pytest.raises(TypeError, match="filename must be text"):
        secure_file.open_secure_file(123, source_name="Credential")  # type: ignore[arg-type]


def test_rejects_non_absolute_trusted_root(monkeypatch) -> None:
    monkeypatch.setattr(secure_file, "SECURE_FILE_ROOT", "relative/root")

    with pytest.raises(RuntimeError, match="root must be absolute"):
        secure_file.open_secure_file("credential", source_name="Credential")


@pytest.mark.parametrize(
    ("mode", "message"),
    [(0o620, "group-writable"), (0o602, "world-writable")],
)
def test_rejects_unsafe_write_permissions(tmp_path, mode, message) -> None:
    path = tmp_path / "credential"
    path.write_bytes(b"secret")
    path.chmod(mode)

    with pytest.raises(secure_file.SecureFileError, match=message):
        secure_file.open_secure_file(path.name, source_name="Credential")


def test_rejects_symlink_without_disclosing_path(tmp_path) -> None:
    target = tmp_path / "sensitive-target"
    target.write_bytes(b"secret")
    link = tmp_path / "sensitive-link"
    link.symlink_to(target)

    with pytest.raises(secure_file.SecureFileError, match="symbolic link") as raised:
        secure_file.open_secure_file(link.name, source_name="Credential")

    assert str(link) not in str(raised.value)


def test_rejects_symlinked_trusted_root_without_disclosing_path(
    monkeypatch, tmp_path
) -> None:
    actual_root = tmp_path / "actual-secrets"
    actual_root.mkdir()
    credential = actual_root / "credential"
    credential.write_bytes(b"secret")
    credential.chmod(0o600)
    linked_root = tmp_path / "linked-secrets"
    linked_root.symlink_to(actual_root, target_is_directory=True)
    monkeypatch.setattr(secure_file, "SECURE_FILE_ROOT", str(linked_root))

    with pytest.raises(secure_file.SecureFileError, match="secure-file root") as raised:
        secure_file.open_secure_file(credential.name, source_name="Credential")

    assert str(linked_root) not in str(raised.value)


def test_rejects_directory_and_fifo_without_blocking(tmp_path) -> None:
    directory = tmp_path / "directory"
    directory.mkdir()
    with pytest.raises(secure_file.SecureFileError, match="not a regular file"):
        secure_file.open_secure_file(directory.name, source_name="Credential")

    if hasattr(os, "mkfifo"):
        fifo = tmp_path / "fifo"
        os.mkfifo(fifo)
        with pytest.raises(secure_file.SecureFileError, match="not a regular file"):
            secure_file.open_secure_file(fifo.name, source_name="Credential")


def test_rejects_untrusted_owner(monkeypatch) -> None:
    monkeypatch.setattr(secure_file.os, "geteuid", lambda: 10001)
    file_status = SimpleNamespace(st_mode=stat.S_IFREG | 0o400, st_uid=20002)

    with pytest.raises(secure_file.SecureFileError, match="untrusted owner"):
        secure_file._check_opened_metadata(file_status, "Credential")


def test_fallback_detects_file_identity_change(monkeypatch, tmp_path) -> None:
    path = tmp_path / "credential"
    path.write_bytes(b"secret")
    path.chmod(0o600)
    actual = os.lstat(path)
    results = iter(
        [
            actual,
            SimpleNamespace(
                st_mode=actual.st_mode,
                st_dev=actual.st_dev,
                st_ino=actual.st_ino + 1,
            ),
        ]
    )
    monkeypatch.delattr(secure_file.os, "O_NOFOLLOW", raising=False)
    monkeypatch.setattr(
        secure_file,
        "_stat_at",
        lambda unused_descriptor, unused_filename: next(results),
    )

    with pytest.raises(secure_file.SecureFileError, match="changed while being opened"):
        secure_file.open_secure_file(path.name, source_name="Credential")
