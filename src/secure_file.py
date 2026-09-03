"""Defensive opening for local files that influence secure behavior."""

import errno
import os
import re
import stat
from typing import BinaryIO

SECURE_FILE_ROOT = "/run/secrets"
MAX_SECURE_FILENAME_CHARS = 255

_SAFE_FILENAME_RE = re.compile(
    rf"[A-Za-z0-9][A-Za-z0-9._-]{{0,{MAX_SECURE_FILENAME_CHARS - 1}}}\Z"
)


class SecureFileError(ValueError):
    """A safe-to-display error for an untrusted local file."""


def _raise_file_error(source_name: str, condition: str) -> None:
    raise SecureFileError(f"{source_name} {condition}") from None


def _raise_open_error(source_name: str) -> None:
    _raise_file_error(source_name, "could not be read")


def _resolve_secure_path(filename: str, source_name: str) -> tuple[str, str, str]:
    if not isinstance(filename, str):
        raise TypeError(f"{source_name} filename must be text")
    if _SAFE_FILENAME_RE.fullmatch(filename) is None or filename in {".", ".."}:
        _raise_file_error(source_name, "filename is invalid")

    trusted_root = os.path.normpath(SECURE_FILE_ROOT)
    if not os.path.isabs(trusted_root):
        raise RuntimeError("secure-file root must be absolute")
    resolved_path = os.path.normpath(os.path.join(trusted_root, filename))
    try:
        contained_root = os.path.commonpath((trusted_root, resolved_path))
    except ValueError:
        _raise_file_error(source_name, "filename is outside the trusted root")
    if contained_root != trusted_root or resolved_path == trusted_root:
        _raise_file_error(source_name, "filename is outside the trusted root")
    contained_name = os.path.relpath(resolved_path, trusted_root)
    return trusted_root, resolved_path, contained_name


def _check_trusted_root_metadata(file_status: os.stat_result) -> None:
    if not stat.S_ISDIR(file_status.st_mode):
        raise SecureFileError("secure-file root is not a trusted directory") from None
    try:
        effective_uid = os.geteuid()
    except AttributeError:
        raise SecureFileError(
            "secure-file root ownership cannot be validated"
        ) from None
    if file_status.st_uid not in {0, effective_uid}:
        raise SecureFileError("secure-file root has an untrusted owner") from None
    if file_status.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise SecureFileError("secure-file root has unsafe permissions") from None


def _open_trusted_root(trusted_root: str) -> int:
    directory_flag = getattr(os, "O_DIRECTORY", 0)
    if (
        not directory_flag
        or os.open not in os.supports_dir_fd
        or os.stat not in os.supports_dir_fd
        or os.stat not in os.supports_follow_symlinks
    ):
        raise RuntimeError("secure-file directory operations are unavailable")

    nofollow = getattr(os, "O_NOFOLLOW", 0)
    flags = os.O_RDONLY | directory_flag
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    before_open = None
    if nofollow:
        flags |= nofollow
    else:
        try:
            before_open = os.lstat(trusted_root)
        except OSError:
            raise SecureFileError("secure-file root could not be read") from None
        if stat.S_ISLNK(before_open.st_mode):
            raise SecureFileError(
                "secure-file root is not a trusted directory"
            ) from None

    try:
        root_descriptor = os.open(trusted_root, flags)
    except OSError:
        raise SecureFileError("secure-file root could not be read") from None

    try:
        try:
            opened_status = os.fstat(root_descriptor)
        except OSError:
            raise SecureFileError(
                "secure-file root cannot be inspected safely"
            ) from None
        _check_trusted_root_metadata(opened_status)

        if before_open is not None:
            try:
                after_open = os.lstat(trusted_root)
            except OSError:
                raise SecureFileError(
                    "secure-file root changed while being opened"
                ) from None
            expected_identity = (before_open.st_dev, before_open.st_ino)
            if (
                stat.S_ISLNK(after_open.st_mode)
                or (after_open.st_dev, after_open.st_ino) != expected_identity
                or (opened_status.st_dev, opened_status.st_ino) != expected_identity
            ):
                raise SecureFileError(
                    "secure-file root changed while being opened"
                ) from None
        return root_descriptor
    except BaseException:
        os.close(root_descriptor)
        raise


def _check_opened_metadata(
    file_status: os.stat_result,
    source_name: str,
    *,
    require_private: bool = False,
) -> None:
    if not stat.S_ISREG(file_status.st_mode):
        _raise_file_error(source_name, "is not a regular file")

    try:
        effective_uid = os.geteuid()
    except AttributeError:
        _raise_file_error(source_name, "ownership cannot be validated")
    if file_status.st_uid not in {0, effective_uid}:
        _raise_file_error(source_name, "has an untrusted owner")

    if file_status.st_mode & stat.S_IWGRP:
        _raise_file_error(source_name, "is group-writable")
    if file_status.st_mode & stat.S_IWOTH:
        _raise_file_error(source_name, "is world-writable")
    if require_private and file_status.st_mode & stat.S_IRGRP:
        _raise_file_error(source_name, "is group-readable")
    if require_private and file_status.st_mode & stat.S_IROTH:
        _raise_file_error(source_name, "is world-readable")


def _stat_at(root_descriptor: int, filename: str) -> os.stat_result:
    return os.stat(
        filename,
        dir_fd=root_descriptor,
        follow_symlinks=False,
    )


def _lstat_for_fallback(
    root_descriptor: int, filename: str, source_name: str
) -> os.stat_result:
    try:
        file_status = _stat_at(root_descriptor, filename)
    except OSError:
        _raise_open_error(source_name)

    if stat.S_ISLNK(file_status.st_mode):
        _raise_file_error(source_name, "is a symbolic link")
    if not stat.S_ISREG(file_status.st_mode):
        _raise_file_error(source_name, "is not a regular file")
    return file_status


def _raise_classified_open_error(
    root_descriptor: int, filename: str, source_name: str
) -> None:
    try:
        file_status = _stat_at(root_descriptor, filename)
    except OSError:
        _raise_open_error(source_name)

    if stat.S_ISLNK(file_status.st_mode):
        _raise_file_error(source_name, "is a symbolic link")
    if not stat.S_ISREG(file_status.st_mode):
        _raise_file_error(source_name, "is not a regular file")
    _raise_open_error(source_name)


def open_secure_file(
    filename: str,
    *,
    source_name: str,
    require_private: bool = False,
) -> BinaryIO:
    """Open one validated filename beneath the fixed secure-file root.

    The final path component is not followed where ``O_NOFOLLOW`` is
    available. Other platforms use matching pre-open, post-open, and descriptor
    identities as a defensive fallback. ``require_private`` additionally
    rejects group/world read access for secret files. Errors intentionally omit
    the path.
    """

    trusted_root, _, contained_name = _resolve_secure_path(filename, source_name)
    root_descriptor = _open_trusted_root(trusted_root)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_BINARY", 0)

    try:
        before_open = None
        if nofollow:
            flags |= nofollow
        else:
            before_open = _lstat_for_fallback(
                root_descriptor,
                contained_name,
                source_name,
            )
        try:
            file_descriptor = os.open(
                contained_name,
                flags,
                dir_fd=root_descriptor,
            )
        except OSError as error:
            if nofollow and error.errno == errno.ELOOP:
                _raise_file_error(source_name, "is a symbolic link")
            _raise_classified_open_error(
                root_descriptor,
                contained_name,
                source_name,
            )

        try:
            try:
                opened_status = os.fstat(file_descriptor)
            except OSError:
                _raise_file_error(source_name, "cannot be inspected safely")
            _check_opened_metadata(
                opened_status,
                source_name,
                require_private=require_private,
            )

            if before_open is not None:
                try:
                    after_open = _stat_at(root_descriptor, contained_name)
                except OSError:
                    _raise_file_error(source_name, "changed while being opened")

                expected_identity = (before_open.st_dev, before_open.st_ino)
                if (
                    stat.S_ISLNK(after_open.st_mode)
                    or (after_open.st_dev, after_open.st_ino) != expected_identity
                    or (opened_status.st_dev, opened_status.st_ino) != expected_identity
                ):
                    _raise_file_error(source_name, "changed while being opened")

            try:
                return os.fdopen(file_descriptor, "rb", closefd=True)
            except OSError:
                _raise_file_error(source_name, "could not be read")
        except BaseException:
            os.close(file_descriptor)
            raise
    finally:
        os.close(root_descriptor)
