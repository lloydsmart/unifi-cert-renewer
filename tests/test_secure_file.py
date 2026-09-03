import os
import stat
from types import SimpleNamespace

import pytest

import secure_file


def test_accepts_regular_file_owned_by_effective_user(tmp_path) -> None:
    path = tmp_path / "credential"
    path.write_bytes(b"secret")
    path.chmod(0o600)

    with secure_file.open_secure_file(str(path), source_name="Credential") as file:
        assert file.read() == b"secret"


@pytest.mark.parametrize(
    ("mode", "message"),
    [(0o620, "group-writable"), (0o602, "world-writable")],
)
def test_rejects_unsafe_write_permissions(tmp_path, mode, message) -> None:
    path = tmp_path / "credential"
    path.write_bytes(b"secret")
    path.chmod(mode)

    with pytest.raises(secure_file.SecureFileError, match=message):
        secure_file.open_secure_file(str(path), source_name="Credential")


def test_rejects_symlink_without_disclosing_path(tmp_path) -> None:
    target = tmp_path / "sensitive-target"
    target.write_bytes(b"secret")
    link = tmp_path / "sensitive-link"
    link.symlink_to(target)

    with pytest.raises(secure_file.SecureFileError, match="symbolic link") as raised:
        secure_file.open_secure_file(str(link), source_name="Credential")

    assert str(link) not in str(raised.value)


def test_rejects_directory_and_fifo_without_blocking(tmp_path) -> None:
    with pytest.raises(secure_file.SecureFileError, match="not a regular file"):
        secure_file.open_secure_file(str(tmp_path), source_name="Credential")

    if hasattr(os, "mkfifo"):
        fifo = tmp_path / "fifo"
        os.mkfifo(fifo)
        with pytest.raises(secure_file.SecureFileError, match="not a regular file"):
            secure_file.open_secure_file(str(fifo), source_name="Credential")


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
    monkeypatch.setattr(secure_file.os, "lstat", lambda unused: next(results))

    with pytest.raises(secure_file.SecureFileError, match="changed while being opened"):
        secure_file.open_secure_file(str(path), source_name="Credential")
