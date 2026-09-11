"""Fixed, dirfd-relative filesystem primitives inside UniFi appdata only."""

import json
import os
import stat
from contextlib import contextmanager

from unifi_client import UnifiOperationError

_ROOT = "/config/data"
CANONICAL = "keystore"
STAGE = ".cert-renewer-stage"
ROLLBACK = ".cert-renewer-rollback"
JOURNAL = ".cert-renewer-journal"
JOURNAL_NEW = ".cert-renewer-journal-new"
LOCK = ".cert-renewer-lock"
_NAMES = {CANONICAL, STAGE, ROLLBACK, JOURNAL, JOURNAL_NEW, LOCK}
_ADMIN = (0, 0)
MAX_STORE = 16 * 1024 * 1024
MAX_JOURNAL = 16384


def _identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mode,
        value.st_uid,
        value.st_gid,
        value.st_mtime_ns,
        value.st_ctime_ns,
        value.st_nlink,
    )


def _filesystem(fd: int) -> str:
    """Return the mounted filesystem type, including through a bind mount.

    The transaction protocol uses only local-filesystem primitives with their
    normal POSIX/Linux semantics.  Btrfs detection remains explicit because its
    anonymous ``st_dev`` limitation is relevant to persisted recovery identity,
    but a different local filesystem is not itself unsafe.
    """
    device = os.fstat(fd).st_dev
    number = f"{os.major(device)}:{os.minor(device)}"
    with open("/proc/self/mountinfo", encoding="ascii") as stream:
        for line in stream:
            fields = line.split()
            if fields[2] == number:
                separator = fields.index("-")
                filesystem = fields[separator + 1]
                if not filesystem or len(filesystem) > 64:
                    break
                return filesystem
    raise UnifiOperationError("cannot identify appdata filesystem")


class _Files:
    def __init__(self, uid: int, gid: int):
        self.uid, self.gid = uid, gid
        self.root = _ROOT
        self.fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            for part in _ROOT.strip("/").split("/"):
                new = os.open(
                    part,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=self.fd,
                )
                os.close(self.fd)
                self.fd = new
                info = os.fstat(new)
                if info.st_uid not in {0, uid} or info.st_mode & 0o022:
                    raise UnifiOperationError("untrusted appdata directory")
            self.filesystem = _filesystem(self.fd)
        except BaseException:
            os.close(self.fd)
            raise

    def close(self):
        os.close(self.fd)

    def _name(self, name):
        directory = os.stat(self.root, follow_symlinks=False)
        opened = os.fstat(self.fd)
        if (
            (directory.st_dev, directory.st_ino) != (opened.st_dev, opened.st_ino)
            or directory.st_uid not in {0, self.uid}
            or directory.st_mode & 0o022
        ):
            raise UnifiOperationError("appdata directory identity changed")
        if name not in _NAMES:
            raise UnifiOperationError("invalid internal filesystem operation")

    def status(self, name):
        self._name(name)
        value = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
        owner = (self.uid, self.gid) if name in {CANONICAL, STAGE, ROLLBACK} else _ADMIN
        if (
            not stat.S_ISREG(value.st_mode)
            or stat.S_IMODE(value.st_mode) != 0o600
            or (value.st_uid, value.st_gid) != owner
            or value.st_dev != os.fstat(self.fd).st_dev
            or not 0 <= value.st_size <= MAX_STORE
            or value.st_nlink not in ({1, 2} if name in {CANONICAL, ROLLBACK} else {1})
        ):
            raise UnifiOperationError("unsafe transaction file")
        return value

    def exists(self, name):
        self._name(name)
        try:
            os.stat(name, dir_fd=self.fd, follow_symlinks=False)
            return True
        except FileNotFoundError:
            return False

    @contextmanager
    def opened(self, name, *, create=False):
        self._name(name)
        flags = os.O_RDWR if create else os.O_RDONLY
        flags |= os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
        if create:
            flags |= os.O_CREAT | os.O_EXCL
        fd = os.open(name, flags, 0o600, dir_fd=self.fd)
        try:
            if create:
                owner = (self.uid, self.gid) if name == STAGE else _ADMIN
                os.fchown(fd, *owner)
                os.fchmod(fd, 0o600)
            if _identity(os.fstat(fd)) != _identity(self.status(name)):
                raise UnifiOperationError("transaction file changed while opening")
            yield fd
        finally:
            os.close(fd)

    def same(self, name, expected):
        if _identity(self.status(name)) != _identity(expected):
            raise UnifiOperationError("transaction file identity changed")

    def copy_stage(self):
        with self.opened(CANONICAL) as source, self.opened(STAGE, create=True) as dest:
            before = self.status(CANONICAL)
            if before.st_nlink != 1:
                raise UnifiOperationError("unexpected canonical hard link")
            remaining = before.st_size
            while remaining:
                # Kernel-to-kernel copy; no keystore bytes enter Python memory.
                copied = os.copy_file_range(source, dest, min(remaining, 1024 * 1024))
                if copied <= 0:
                    raise UnifiOperationError("incomplete staged copy")
                remaining -= copied
            self.same(CANONICAL, before)
            if os.fstat(dest).st_ino == before.st_ino:
                raise UnifiOperationError("stage must be an independent inode")

    def sync_file(self, name):
        with self.opened(name) as fd:
            os.fsync(fd)

    def sync_directory(self):
        os.fsync(self.fd)

    def link_rollback(self):
        self.status(CANONICAL)
        os.link(
            CANONICAL,
            ROLLBACK,
            src_dir_fd=self.fd,
            dst_dir_fd=self.fd,
            follow_symlinks=False,
        )

    def replace(self, source, target):
        if (source, target) not in {
            (STAGE, CANONICAL),
            (ROLLBACK, CANONICAL),
            (JOURNAL_NEW, JOURNAL),
        }:
            raise UnifiOperationError("invalid internal replacement")
        self.status(source)
        os.replace(source, target, src_dir_fd=self.fd, dst_dir_fd=self.fd)

    def remove(self, name):
        if name not in {STAGE, ROLLBACK, JOURNAL, JOURNAL_NEW}:
            raise UnifiOperationError("invalid internal cleanup")
        if self.exists(name):
            self.status(name)
            os.unlink(name, dir_fd=self.fd)

    def write_journal(self, value):
        data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
        if len(data) > MAX_JOURNAL:
            raise UnifiOperationError("journal exceeds limit")
        # A crash may leave the previous temporary journal; only this fixed,
        # root-owned regular file may be removed under exclusion.
        self.remove(JOURNAL_NEW)
        with self.opened(JOURNAL_NEW, create=True) as fd:
            view = memoryview(data)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise UnifiOperationError("journal write failed")
                view = view[written:]
            os.fsync(fd)
        self.replace(JOURNAL_NEW, JOURNAL)
        self.sync_directory()

    def read_journal(self):
        with self.opened(JOURNAL) as fd:
            data = os.read(fd, MAX_JOURNAL + 1)
        if len(data) > MAX_JOURNAL:
            raise UnifiOperationError("journal exceeds limit")

        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError
                result[key] = value
            return result

        return json.loads(data, object_pairs_hook=unique)
