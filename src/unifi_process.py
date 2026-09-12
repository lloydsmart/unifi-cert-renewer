"""Private Linux process primitives for the key-owner-local executor.

No command runner is exposed by the execution boundary. Diagnostics are discarded.
The inherited flock descriptor keeps recovery excluded if the parent dies.
"""

import contextlib
import errno
import os
import selectors
import signal
import subprocess
import time
from pathlib import Path

from unifi_client import UnifiOperationError

MAX_IO = 1024 * 1024
TIMEOUT = 30.0
SERVICE = "/run/service/svc-unifi-network-application"
ABC_UID = 1000
ABC_GID = 1000
PROCESS_INSPECTION_TIMEOUT = 2.0
MAX_PROCESS_STATUS = 16 * 1024
_PROCESS_RESULTS = {
    b"N": (False, False),
    b"U": (True, False),
    b"K": (False, True),
    b"B": (True, True),
}


class _ProcessDisappeared(Exception):
    """The anchored target process exited during proc inspection."""


def _target_error(error: OSError) -> None:
    if error.errno in {errno.ENOENT, errno.ESRCH}:
        raise _ProcessDisappeared from None
    raise error


def _open_process(process: Path) -> int:
    try:
        return os.open(
            process,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
    except OSError as error:
        _target_error(error)


def _target_fstat(process_fd: int):
    try:
        return os.fstat(process_fd)
    except OSError as error:
        _target_error(error)


def _reap(child: subprocess.Popen) -> None:
    """Terminate the isolated group, escalate, and reap before returning."""
    with contextlib.suppress(ProcessLookupError):
        os.killpg(child.pid, signal.SIGTERM)
    with contextlib.suppress(subprocess.TimeoutExpired):
        child.wait(timeout=2)
    # Also kill descendants that retained pipes after the immediate child exited.
    with contextlib.suppress(ProcessLookupError):
        os.killpg(child.pid, signal.SIGKILL)
    child.wait()  # A killed, uninterruptible kernel task must retain exclusion.


def _run(argv: tuple[str, ...], data: bytes, env: dict[str, str], lock: int) -> bytes:
    """Bound both streams while concurrently feeding bounded public stdin."""
    child = None
    try:
        if not isinstance(data, bytes) or len(data) > MAX_IO:
            raise ValueError
        child = subprocess.Popen(
            argv,
            shell=False,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            start_new_session=True,
            close_fds=True,
            pass_fds=(lock,),
        )
        deadline = time.monotonic() + TIMEOUT
        output = bytearray()
        errors = 0
        sent = 0
        with selectors.DefaultSelector() as selector:
            for stream in (child.stdout, child.stderr, child.stdin):
                os.set_blocking(stream.fileno(), False)
            selector.register(child.stdout, selectors.EVENT_READ)
            selector.register(child.stderr, selectors.EVENT_READ)
            if data:
                selector.register(child.stdin, selectors.EVENT_WRITE)
            else:
                child.stdin.close()
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError
                for key, _ in selector.select(min(remaining, 0.1)):
                    stream = key.fileobj
                    if stream is child.stdin:
                        try:
                            sent += os.write(stream.fileno(), data[sent : sent + 4096])
                        except BrokenPipeError:
                            sent = len(data)
                        if sent == len(data):
                            selector.unregister(stream)
                            stream.close()
                    else:
                        chunk = os.read(stream.fileno(), 4096)
                        if not chunk:
                            selector.unregister(stream)
                            stream.close()
                        elif stream is child.stdout:
                            output.extend(chunk)
                        else:
                            errors += len(chunk)
                        if len(output) > MAX_IO or errors > MAX_IO:
                            raise ValueError
            status = child.wait(timeout=max(0.001, deadline - time.monotonic()))
            if status != 0:
                raise ValueError
        return bytes(output)
    except Exception:
        raise UnifiOperationError("UniFi child execution failed") from None
    finally:
        if child is not None:
            _reap(child)
            for stream in (child.stdin, child.stdout, child.stderr):
                stream.close()


def _read_at(process_fd: int, name: str, maximum: int) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        fd = os.open(name, flags, dir_fd=process_fd)
    except OSError as error:
        _target_error(error)
    try:
        result = bytearray()
        while len(result) <= maximum:
            try:
                chunk = os.read(fd, min(4096, maximum + 1 - len(result)))
            except OSError as error:
                _target_error(error)
            if not chunk:
                return bytes(result)
            result.extend(chunk)
        raise UnifiOperationError("process data exceeds inspection limit")
    finally:
        os.close(fd)


def _inspect_process_fd(process_fd: int) -> tuple[bool, bool]:
    """Identify one real Java/ace.jar or keytool process from an anchored fd."""
    # Linux retains the executable inode for a running process after package
    # replacement/unlink and annotates its proc symlink target.
    try:
        target = os.readlink("exe", dir_fd=process_fd)
    except OSError as error:
        _target_error(error)
    executable = Path(target.removesuffix(" (deleted)")).name
    if executable not in {"java", "keytool"}:
        return False, False
    command = _read_at(process_fd, "cmdline", 65536)
    args = command.split(b"\0")
    keytool = executable == "keytool" or b"sun.security.tools.keytool.Main" in args
    unifi = executable == "java" and any(
        args[index : index + 3] == [b"-jar", b"/usr/lib/unifi/lib/ace.jar", b"start"]
        for index in range(len(args))
    )
    return unifi, keytool


def _inspect_process(process: Path) -> tuple[bool, bool]:
    """Identify a process while anchoring all reads to its proc directory."""
    fd = _open_process(process)
    try:
        return _inspect_process_fd(fd)
    finally:
        os.close(fd)


def _abc_process_identity(process_fd: int) -> tuple[int, int, int, int]:
    """Prove an anchored process has the complete fixed LinuxServer identity."""
    before = _target_fstat(process_fd)
    if (before.st_uid, before.st_gid) != (ABC_UID, ABC_GID):
        raise UnifiOperationError("cannot establish process exclusion")
    status = _read_at(process_fd, "status", MAX_PROCESS_STATUS)
    fields = {}
    for line in status.splitlines():
        name, separator, value = line.partition(b":")
        if separator and name in {b"Uid", b"Gid"}:
            if name in fields:
                raise UnifiOperationError("cannot establish process exclusion")
            try:
                fields[name] = tuple(int(item) for item in value.split())
            except ValueError:
                raise UnifiOperationError(
                    "cannot establish process exclusion"
                ) from None
    if fields != {b"Uid": (ABC_UID,) * 4, b"Gid": (ABC_GID,) * 4}:
        raise UnifiOperationError("cannot establish process exclusion")
    after = _target_fstat(process_fd)
    identity = (before.st_dev, before.st_ino, before.st_uid, before.st_gid)
    if identity != (after.st_dev, after.st_ino, after.st_uid, after.st_gid):
        raise UnifiOperationError("cannot establish process exclusion")
    return identity


def _close_child_fds(process_fd: int, result_fd: int) -> None:
    """Leave the inspection child only its anchored proc fd and result pipe."""
    retained = {process_fd, result_fd}
    for name in os.listdir("/proc/self/fd"):
        fd = int(name)
        if fd not in retained:
            with contextlib.suppress(OSError):
                os.close(fd)


def _drop_inspection_identity() -> None:
    os.setgroups([])
    os.setresgid(ABC_GID, ABC_GID, ABC_GID)
    os.setresuid(ABC_UID, ABC_UID, ABC_UID)
    if (
        os.getgroups()
        or os.getresgid() != (ABC_GID,) * 3
        or os.getresuid() != (ABC_UID,) * 3
    ):
        raise OSError


def _child_inspection(process_fd: int, result_fd: int) -> None:
    """Drop permanently to abc, inspect one anchored process, and exit."""
    result = b"E"
    try:
        _close_child_fds(process_fd, result_fd)
        _drop_inspection_identity()
        found = _inspect_process_fd(process_fd)
        result = {value: key for key, value in _PROCESS_RESULTS.items()}[found]
    except _ProcessDisappeared:
        result = b"D"
    except BaseException:
        pass
    with contextlib.suppress(OSError):
        os.write(result_fd, result)
    os._exit(0)


def _kill_and_reap(pid: int) -> None:
    with contextlib.suppress(ProcessLookupError):
        os.kill(pid, signal.SIGKILL)
    while True:
        try:
            os.waitpid(pid, 0)
            return
        except InterruptedError:
            continue
        except ChildProcessError:
            return


def _receive_child(pid: int, result_fd: int) -> tuple[bool, bool]:
    deadline = time.monotonic() + PROCESS_INSPECTION_TIMEOUT
    output = bytearray()
    status = None
    eof = False
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(result_fd, selectors.EVENT_READ)
            while status is None or not eof:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise UnifiOperationError("cannot establish process exclusion")
                if not eof:
                    for _key, _events in selector.select(min(remaining, 0.05)):
                        chunk = os.read(result_fd, 2)
                        if chunk:
                            output.extend(chunk)
                            if len(output) > 1:
                                raise UnifiOperationError(
                                    "cannot establish process exclusion"
                                )
                        else:
                            selector.unregister(result_fd)
                            eof = True
                if status is None:
                    waited, child_status = os.waitpid(pid, os.WNOHANG)
                    if waited:
                        status = child_status
        if os.waitstatus_to_exitcode(status) != 0 or len(output) != 1:
            raise UnifiOperationError("cannot establish process exclusion")
        if bytes(output) == b"D":
            raise _ProcessDisappeared
        try:
            return _PROCESS_RESULTS[bytes(output)]
        except KeyError:
            raise UnifiOperationError("cannot establish process exclusion") from None
    finally:
        os.close(result_fd)
        if status is None:
            _kill_and_reap(pid)


def _inspect_as_abc(process_fd: int) -> tuple[bool, bool]:
    """Inspect only one internally selected process as fixed uid/gid 1000."""
    read_fd, write_fd = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        pid = os.fork()
    except BaseException:
        os.close(read_fd)
        os.close(write_fd)
        raise
    if pid == 0:
        os.close(read_fd)
        _child_inspection(process_fd, write_fd)
        os._exit(1)
    os.close(write_fd)
    return _receive_child(pid, read_fd)


def _processes() -> tuple[bool, bool]:
    """Identify real Java/ace.jar and keytool executables, never shell text.

    Require a full /proc view. Permission errors fail closed. Disappearing PIDs
    are normal; the service-down state prevents a replacement UniFi JVM.
    """
    unifi = keytool = False
    for process in Path("/proc").iterdir():
        if not process.name.isdecimal():
            continue
        process_fd = None
        try:
            process_fd = _open_process(process)
            try:
                found_unifi, found_keytool = _inspect_process_fd(process_fd)
            except PermissionError:
                identity = _abc_process_identity(process_fd)
                try:
                    found_unifi, found_keytool = _inspect_as_abc(process_fd)
                except _ProcessDisappeared:
                    try:
                        _abc_process_identity(process_fd)
                    except _ProcessDisappeared:
                        raise
                    raise UnifiOperationError(
                        "cannot establish process exclusion"
                    ) from None
                if identity != _abc_process_identity(process_fd):
                    raise UnifiOperationError(
                        "cannot establish process exclusion"
                    ) from None
            unifi |= found_unifi
            keytool |= found_keytool
        except _ProcessDisappeared:
            continue
        except OSError:
            raise UnifiOperationError("cannot establish process exclusion") from None
        finally:
            if process_fd is not None:
                os.close(process_fd)
    return unifi, keytool


class _Service:
    def __init__(self, lock: int):
        self.lock = lock

    def _command(self, *args: str) -> bytes:
        return _run(args, b"", {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}, self.lock)

    def running(self) -> bool:
        result = self._command("/usr/bin/s6-svstat", "-o", "up,ready", SERVICE).strip()
        if result == b"true true":
            return True
        if result == b"false false":
            return False
        raise UnifiOperationError("UniFi service is not in a stable state")

    def no_keytool(self) -> None:
        if _processes()[1]:
            raise UnifiOperationError("surviving keytool prevents execution")

    def stopped(self) -> None:
        unifi, keytool = _processes()
        if unifi or keytool or self.running():
            raise UnifiOperationError("UniFi writer exclusion failed")

    def stop(self) -> None:
        self.no_keytool()
        self._command("/usr/bin/s6-svc", "-wD", "-T", "25000", "-d", SERVICE)
        self.stopped()

    def start(self) -> None:
        self.no_keytool()
        self._command("/usr/bin/s6-svc", "-wU", "-T", "25000", "-u", SERVICE)
        if not self.running() or not _processes()[0]:
            raise UnifiOperationError("UniFi service readiness failed")
