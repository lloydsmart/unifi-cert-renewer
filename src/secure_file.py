"""Defensive opening for local files that influence secure behavior."""

import errno
import os
import stat
from typing import BinaryIO


class SecureFileError(ValueError):
    """A safe-to-display error for an untrusted local file."""


def _raise_file_error(source_name: str, condition: str) -> None:
    raise SecureFileError(f"{source_name} {condition}") from None


def _raise_open_error(source_name: str) -> None:
    _raise_file_error(source_name, "could not be read")


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


def _lstat_for_fallback(path: str, source_name: str) -> os.stat_result:
    try:
        file_status = os.lstat(path)
    except OSError:
        _raise_open_error(source_name)

    if stat.S_ISLNK(file_status.st_mode):
        _raise_file_error(source_name, "is a symbolic link")
    if not stat.S_ISREG(file_status.st_mode):
        _raise_file_error(source_name, "is not a regular file")
    return file_status


def _raise_classified_open_error(path: str, source_name: str) -> None:
    try:
        file_status = os.lstat(path)
    except OSError:
        _raise_open_error(source_name)

    if stat.S_ISLNK(file_status.st_mode):
        _raise_file_error(source_name, "is a symbolic link")
    if not stat.S_ISREG(file_status.st_mode):
        _raise_file_error(source_name, "is not a regular file")
    _raise_open_error(source_name)


def open_secure_file(
    path: str,
    *,
    source_name: str,
    require_private: bool = False,
) -> BinaryIO:
    """Open and validate an existing security-sensitive file as binary.

    The final path component is not followed where ``O_NOFOLLOW`` is
    available. Other platforms use matching pre-open, post-open, and descriptor
    identities as a defensive fallback. ``require_private`` additionally
    rejects group/world read access for secret files. Errors intentionally omit
    the path.
    """

    nofollow = getattr(os, "O_NOFOLLOW", 0)
    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_BINARY", 0)

    before_open = None
    if nofollow:
        flags |= nofollow
    else:
        before_open = _lstat_for_fallback(path, source_name)

    try:
        file_descriptor = os.open(path, flags)
    except OSError as error:
        if nofollow and error.errno == errno.ELOOP:
            _raise_file_error(source_name, "is a symbolic link")
        _raise_classified_open_error(path, source_name)

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
                after_open = os.lstat(path)
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
