"""Private Linux process primitives for the key-owner-local executor.

No command runner is exposed by the execution boundary. Diagnostics are discarded.
The inherited flock descriptor keeps recovery excluded if the parent dies.
"""

import contextlib
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


def _inspect_process(process: Path) -> tuple[bool, bool]:
    """Identify a single real Java/ace.jar or keytool process from /proc data."""
    # Linux retains the executable inode for a running process after package
    # replacement/unlink and annotates its proc symlink target.
    executable = Path(os.readlink(process / "exe").removesuffix(" (deleted)")).name
    if executable not in {"java", "keytool"}:
        return False, False
    with (process / "cmdline").open("rb") as stream:
        command = stream.read(65537)
    if len(command) > 65536:
        raise UnifiOperationError("process command exceeds inspection limit")
    args = command.split(b"\0")
    keytool = executable == "keytool" or b"sun.security.tools.keytool.Main" in args
    unifi = executable == "java" and any(
        args[index : index + 3] == [b"-jar", b"/usr/lib/unifi/lib/ace.jar", b"start"]
        for index in range(len(args))
    )
    return unifi, keytool


def _processes() -> tuple[bool, bool]:
    """Identify real Java/ace.jar and keytool executables, never shell text.

    Require a full /proc view. Permission errors fail closed. Disappearing PIDs
    are normal; the service-down state prevents a replacement UniFi JVM.
    """
    unifi = keytool = False
    for process in Path("/proc").iterdir():
        if not process.name.isdecimal():
            continue
        try:
            found_unifi, found_keytool = _inspect_process(process)
            unifi |= found_unifi
            keytool |= found_keytool
        except FileNotFoundError:
            continue
        except OSError:
            raise UnifiOperationError("cannot establish process exclusion") from None
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
