import contextlib
import errno
import fcntl
import inspect
import os
import shutil
import signal
import subprocess
import sys
import time
import traceback
from pathlib import Path
from types import SimpleNamespace

import pytest

import unifi_process as process
from unifi_client import UnifiOperationError


@pytest.fixture
def lock(tmp_path):
    with (tmp_path / "lock").open("w+b") as stream:
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
        yield stream.fileno()


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_stream_limits_kill_and_reap(lock, monkeypatch, stream):
    monkeypatch.setattr(process, "MAX_IO", 8192)
    children = []
    original = subprocess.Popen

    def spawn(*args, **kwargs):
        assert kwargs["shell"] is False
        assert kwargs["pass_fds"] == (lock,)
        child = original(*args, **kwargs)
        children.append(child)
        return child

    monkeypatch.setattr(process.subprocess, "Popen", spawn)
    code = f"import sys,time; sys.{stream}.write('x'*20000); sys.{stream}.flush(); time.sleep(20)"
    with pytest.raises(UnifiOperationError):
        process._run((sys.executable, "-c", code), b"", {}, lock)
    assert children[0].returncode is not None
    with pytest.raises(ChildProcessError):
        os.waitpid(children[0].pid, os.WNOHANG)


def test_deadline_escalates_sigterm_ignoring_child(lock, monkeypatch):
    monkeypatch.setattr(process, "TIMEOUT", 0.25)
    children = []
    original = subprocess.Popen

    def spawn(*args, **kwargs):
        child = original(*args, **kwargs)
        children.append(child)
        return child

    monkeypatch.setattr(process.subprocess, "Popen", spawn)
    code = "import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(20)"
    start = time.monotonic()
    with pytest.raises(UnifiOperationError):
        process._run((sys.executable, "-c", code), b"", {}, lock)
    assert time.monotonic() - start < 5
    assert children[0].returncode == -signal.SIGKILL


def test_interruption_still_reaps_child(lock, monkeypatch):
    children = []
    original = subprocess.Popen

    def spawn(*args, **kwargs):
        child = original(*args, **kwargs)
        children.append(child)
        return child

    monkeypatch.setattr(process.subprocess, "Popen", spawn)

    def interrupt(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(process.selectors.EpollSelector, "select", interrupt)
    with pytest.raises(KeyboardInterrupt):
        process._run(
            (sys.executable, "-c", "import time; time.sleep(20)"), b"", {}, lock
        )
    assert children[0].returncode is not None


def test_io_and_secret_diagnostics_are_not_exposed(lock, capsys):
    code = "import sys; data=sys.stdin.buffer.read(); sys.stdout.buffer.write(data)"
    data = b"public" * 10000
    assert process._run((sys.executable, "-c", code), data, {}, lock) == data
    with pytest.raises(UnifiOperationError) as raised:
        process._run(
            (
                sys.executable,
                "-c",
                "import sys; print('synthetic-secret'); sys.exit(1)",
            ),
            b"",
            {},
            lock,
        )
    assert "synthetic-secret" not in "".join(traceback.format_exception(raised.value))
    assert capsys.readouterr() == ("", "")


def test_surviving_child_retains_lock_after_parent_death(tmp_path):
    path = tmp_path / "lock"
    path.touch()
    code = """
import fcntl,os,subprocess,sys
fd=os.open(sys.argv[1],os.O_RDONLY)
fcntl.flock(fd,fcntl.LOCK_EX)
child=subprocess.Popen([sys.executable,"-c","import time; time.sleep(20)"],pass_fds=(fd,),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
print(child.pid,flush=True)
os._exit(0)
"""
    parent = subprocess.Popen(
        (sys.executable, "-c", code, str(path)), stdout=subprocess.PIPE, text=True
    )
    child_pid = int(parent.stdout.readline())
    parent.wait(timeout=5)
    parent.stdout.close()
    try:
        with path.open("rb") as probe:
            with pytest.raises(BlockingIOError):
                fcntl.flock(probe.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            os.kill(child_pid, signal.SIGKILL)
            deadline = time.monotonic() + 5
            while True:
                try:
                    fcntl.flock(probe.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() > deadline:
                        pytest.fail("orphan retained lock after termination")
                    time.sleep(0.01)
    finally:
        with contextlib.suppress(ProcessLookupError):
            os.kill(child_pid, signal.SIGKILL)


@pytest.mark.parametrize(
    "exe,args,expected",
    [
        ("java", b"java\0-jar\0/usr/lib/unifi/lib/ace.jar\0start\0", (True, False)),
        (
            "bash",
            b"bash\0-c\0java -jar /usr/lib/unifi/lib/ace.jar start\0",
            (False, False),
        ),
        ("java", b"java\0-jar\0/other/ace.jar\0start\0", (False, False)),
        ("keytool", b"keytool\0-importcert\0", (False, True)),
        ("keytool (deleted)", b"keytool\0-importcert\0", (False, True)),
        (
            "java (deleted)",
            b"java\0-jar\0/usr/lib/unifi/lib/ace.jar\0start\0",
            (True, False),
        ),
        (
            "java (deleted)",
            b"java\0sun.security.tools.keytool.Main\0",
            (False, True),
        ),
        ("java", b"java\0sun.security.tools.keytool.Main\0", (False, True)),
    ],
)
def test_proc_matches_executable_and_exact_jar_arguments(
    tmp_path, monkeypatch, exe, args, expected
):
    pid = tmp_path / "123"
    pid.mkdir()
    (pid / "exe").symlink_to(f"/usr/bin/{exe}")
    (pid / "cmdline").write_bytes(args)
    monkeypatch.setattr(
        process, "Path", lambda value: tmp_path if value == "/proc" else Path(value)
    )
    assert process._processes() == expected


def test_unlinked_executable_remains_a_detected_writer(tmp_path):
    # A harmless native process exercises the real Linux /proc suffix without
    # requiring Java, a keystore, or an actual writer.
    executable = tmp_path / "keytool"
    shutil.copyfile("/bin/sleep", executable)
    executable.chmod(0o700)
    child = subprocess.Popen((str(executable), "20"))
    try:
        child_process = Path(f"/proc/{child.pid}")
        assert process._inspect_process(child_process) == (False, True)
        executable.unlink()
        assert os.readlink(f"/proc/{child.pid}/exe").endswith(" (deleted)")
        assert process._inspect_process(child_process) == (False, True)
    finally:
        child.kill()
        child.wait(timeout=5)


def test_proc_permission_failure_is_not_assumed_absence(tmp_path, monkeypatch):
    pid = tmp_path / "123"
    pid.mkdir()
    (pid / "status").write_bytes(
        b"Uid:\t1001\t1001\t1001\t1001\nGid:\t1001\t1001\t1001\t1001\n"
    )
    monkeypatch.setattr(
        process, "Path", lambda value: tmp_path if value == "/proc" else Path(value)
    )

    def denied(*args, **kwargs):
        raise PermissionError

    monkeypatch.setattr(process.os, "readlink", denied)
    with pytest.raises(UnifiOperationError):
        process._processes()


def _proc_entry(tmp_path, command, executable="java", *, uid=1000, gid=1000):
    pid = tmp_path / "123"
    pid.mkdir()
    (pid / "exe").symlink_to(f"/usr/bin/{executable}")
    (pid / "cmdline").write_bytes(command)
    (pid / "status").write_bytes(
        (
            f"Name:\tjava\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n"
            f"Gid:\t{gid}\t{gid}\t{gid}\t{gid}\n"
        ).encode()
    )
    return pid


def test_fixed_abc_fallback_classifies_genuine_unifi(tmp_path, monkeypatch):
    uid, gid = os.getuid(), os.getgid()
    _proc_entry(
        tmp_path,
        b"java\0-Xmx1024M\0-jar\0/usr/lib/unifi/lib/ace.jar\0start\0",
        uid=uid,
        gid=gid,
    )
    monkeypatch.setattr(
        process, "Path", lambda value: tmp_path if value == "/proc" else Path(value)
    )
    monkeypatch.setattr(process, "ABC_UID", uid)
    monkeypatch.setattr(process, "ABC_GID", gid)
    original = process._inspect_process_fd

    def cross_uid_denial(process_fd):
        if os.getpid() == parent_pid:
            raise PermissionError
        return original(process_fd)

    parent_pid = os.getpid()
    monkeypatch.setattr(process, "_inspect_process_fd", cross_uid_denial)
    monkeypatch.setattr(process, "_drop_inspection_identity", lambda: None)
    assert process._processes() == (True, False)


def test_fallback_is_not_available_for_other_identity(tmp_path, monkeypatch):
    _proc_entry(tmp_path, b"java\0-jar\0/usr/lib/unifi/lib/ace.jar\0start\0")
    monkeypatch.setattr(
        process, "Path", lambda value: tmp_path if value == "/proc" else Path(value)
    )
    monkeypatch.setattr(
        process,
        "_inspect_process_fd",
        lambda _fd: (_ for _ in ()).throw(PermissionError()),
    )
    monkeypatch.setattr(
        process,
        "_abc_process_identity",
        lambda _fd: (_ for _ in ()).throw(
            UnifiOperationError("cannot establish process exclusion")
        ),
    )
    called = False

    def fallback(_fd):
        nonlocal called
        called = True

    monkeypatch.setattr(process, "_inspect_as_abc", fallback)
    with pytest.raises(UnifiOperationError):
        process._processes()
    assert not called


def test_fixed_fallback_has_no_caller_selected_identity_or_command():
    assert tuple(inspect.signature(process._inspect_as_abc).parameters) == (
        "process_fd",
    )
    assert (process.ABC_UID, process.ABC_GID) == (1000, 1000)


def test_privilege_drop_clears_groups_and_all_saved_ids(monkeypatch):
    calls = []
    monkeypatch.setattr(process.os, "setgroups", lambda groups: calls.append(groups))
    monkeypatch.setattr(
        process.os, "setresgid", lambda *ids: calls.append(("gid", ids))
    )
    monkeypatch.setattr(
        process.os, "setresuid", lambda *ids: calls.append(("uid", ids))
    )
    monkeypatch.setattr(process.os, "getgroups", lambda: [])
    monkeypatch.setattr(process.os, "getresgid", lambda: (1000, 1000, 1000))
    monkeypatch.setattr(process.os, "getresuid", lambda: (1000, 1000, 1000))
    process._drop_inspection_identity()
    assert calls == [
        [],
        ("gid", (1000, 1000, 1000)),
        ("uid", (1000, 1000, 1000)),
    ]


def test_same_uid_inspection_still_requires_executable(monkeypatch):
    read_fd, write_fd = os.pipe()
    os.close(read_fd)

    def denied(_fd):
        raise PermissionError

    monkeypatch.setattr(process, "_inspect_process_fd", denied)
    monkeypatch.setattr(process, "_drop_inspection_identity", lambda: None)
    with pytest.raises(UnifiOperationError):
        process._inspect_as_abc(write_fd)
    os.close(write_fd)


def test_privilege_drop_failure_fails_closed(tmp_path, monkeypatch):
    pid = _proc_entry(tmp_path, b"java\0-jar\0/usr/lib/unifi/lib/ace.jar\0start\0")
    fd = os.open(pid, os.O_RDONLY | os.O_DIRECTORY)
    monkeypatch.setattr(
        process,
        "_drop_inspection_identity",
        lambda: (_ for _ in ()).throw(OSError()),
    )
    try:
        with pytest.raises(UnifiOperationError):
            process._inspect_as_abc(fd)
    finally:
        os.close(fd)


@pytest.mark.parametrize("result", [b"XX", None])
def test_child_corruption_or_unexpected_exit_fails_closed(
    tmp_path, monkeypatch, result
):
    pid = _proc_entry(tmp_path, b"java\0-jar\0/usr/lib/unifi/lib/ace.jar\0start\0")
    fd = os.open(pid, os.O_RDONLY | os.O_DIRECTORY)

    def child(_process_fd, result_fd):
        if result is not None:
            os.write(result_fd, result)
        os._exit(7 if result is None else 0)

    monkeypatch.setattr(process, "_child_inspection", child)
    try:
        with pytest.raises(UnifiOperationError):
            process._inspect_as_abc(fd)
    finally:
        os.close(fd)


def test_child_wait_is_bounded_and_child_is_reaped(tmp_path, monkeypatch):
    pid = _proc_entry(tmp_path, b"java\0-jar\0/usr/lib/unifi/lib/ace.jar\0start\0")
    fd = os.open(pid, os.O_RDONLY | os.O_DIRECTORY)
    reaped = []
    original = process._kill_and_reap

    def child(_process_fd, _result_fd):
        time.sleep(20)
        os._exit(0)

    def kill_and_reap(child_pid):
        original(child_pid)
        reaped.append(child_pid)

    monkeypatch.setattr(process, "PROCESS_INSPECTION_TIMEOUT", 0.1)
    monkeypatch.setattr(process, "_child_inspection", child)
    monkeypatch.setattr(process, "_kill_and_reap", kill_and_reap)
    started = time.monotonic()
    try:
        with pytest.raises(UnifiOperationError):
            process._inspect_as_abc(fd)
    finally:
        os.close(fd)
    assert time.monotonic() - started < 2
    with pytest.raises(ChildProcessError):
        os.waitpid(reaped[0], os.WNOHANG)


def _result_child(result, *, exit_delay=0):
    read_fd, write_fd = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
    pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        os.write(write_fd, result)
        os.close(write_fd)
        time.sleep(exit_delay)
        os._exit(0)
    os.close(write_fd)
    return pid, read_fd


def test_receive_drains_eof_after_reaping_exited_child_once():
    pid, read_fd = _result_child(b"U")
    deadline = time.monotonic() + 2
    while True:
        with open(f"/proc/{pid}/stat", "rb") as status:
            state = status.read().split()[2]
        if state == b"Z":
            break
        if time.monotonic() >= deadline:
            pytest.fail("result child did not exit")
        time.sleep(0.01)
    assert process._receive_child(pid, read_fd) == (True, False)
    with pytest.raises(ChildProcessError):
        os.waitpid(pid, os.WNOHANG)


def test_receive_drains_eof_before_collecting_child_once():
    pid, read_fd = _result_child(b"K", exit_delay=0.2)
    assert process._receive_child(pid, read_fd) == (False, True)
    with pytest.raises(ChildProcessError):
        os.waitpid(pid, os.WNOHANG)


def _terminated_process_fd():
    child = subprocess.Popen(("/bin/sleep", "20"))
    process_fd = os.open(
        f"/proc/{child.pid}", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    )
    child.kill()
    child.wait(timeout=5)
    return process_fd


def test_anchored_direct_process_exit_is_disappearance():
    process_fd = _terminated_process_fd()
    try:
        with pytest.raises(process._ProcessDisappeared):
            process._inspect_process_fd(process_fd)
    finally:
        os.close(process_fd)


def test_anchored_same_uid_process_exit_is_disappearance(monkeypatch):
    process_fd = _terminated_process_fd()
    monkeypatch.setattr(process, "_drop_inspection_identity", lambda: None)
    try:
        with pytest.raises(process._ProcessDisappeared):
            process._inspect_as_abc(process_fd)
    finally:
        os.close(process_fd)


@pytest.mark.parametrize("number", [errno.ENOENT, errno.ESRCH])
def test_only_target_enoent_and_esrch_are_disappearance(number):
    with pytest.raises(process._ProcessDisappeared):
        process._target_error(OSError(number, "target unavailable"))


def test_malformed_abc_status_remains_fatal(tmp_path, monkeypatch):
    pid = tmp_path / "123"
    pid.mkdir()
    (pid / "status").write_bytes(b"Uid:\tinvalid\nGid:\t1000\t1000\t1000\t1000\n")
    process_fd = os.open(pid, os.O_RDONLY | os.O_DIRECTORY)
    identity = SimpleNamespace(st_dev=1, st_ino=2, st_uid=1000, st_gid=1000)
    monkeypatch.setattr(process, "_target_fstat", lambda _fd: identity)
    try:
        with pytest.raises(UnifiOperationError):
            process._abc_process_identity(process_fd)
    finally:
        os.close(process_fd)


def test_abc_proc_ownership_mismatch_remains_fatal(monkeypatch):
    identity = SimpleNamespace(st_dev=1, st_ino=2, st_uid=1001, st_gid=1000)
    monkeypatch.setattr(process, "_target_fstat", lambda _fd: identity)
    with pytest.raises(UnifiOperationError):
        process._abc_process_identity(123)


def test_unrelated_proc_oserror_remains_fatal(tmp_path, monkeypatch):
    (tmp_path / "123").mkdir()
    monkeypatch.setattr(
        process, "Path", lambda value: tmp_path if value == "/proc" else Path(value)
    )
    monkeypatch.setattr(
        process,
        "_inspect_process_fd",
        lambda _fd: (_ for _ in ()).throw(OSError(errno.EIO, "unrelated")),
    )
    with pytest.raises(UnifiOperationError):
        process._processes()


def test_disappearing_process_remains_tolerated(tmp_path, monkeypatch):
    (tmp_path / "123").mkdir()
    monkeypatch.setattr(
        process, "Path", lambda value: tmp_path if value == "/proc" else Path(value)
    )
    monkeypatch.setattr(
        process,
        "_inspect_process_fd",
        lambda _fd: (_ for _ in ()).throw(process._ProcessDisappeared()),
    )
    assert process._processes() == (False, False)


def test_ownership_change_after_fallback_fails_closed(tmp_path, monkeypatch):
    _proc_entry(tmp_path, b"java\0-jar\0/usr/lib/unifi/lib/ace.jar\0start\0")
    monkeypatch.setattr(
        process, "Path", lambda value: tmp_path if value == "/proc" else Path(value)
    )
    monkeypatch.setattr(
        process,
        "_inspect_process_fd",
        lambda _fd: (_ for _ in ()).throw(PermissionError()),
    )
    identities = iter(((1, 2, 1000, 1000), (1, 3, 1000, 1000)))
    monkeypatch.setattr(process, "_abc_process_identity", lambda _fd: next(identities))
    monkeypatch.setattr(process, "_inspect_as_abc", lambda _fd: (True, False))
    with pytest.raises(UnifiOperationError):
        process._processes()


def test_s6_uses_bounded_down_and_readiness_wait_and_checks_actual_java(
    lock, monkeypatch
):
    calls = []
    alive = [True, False]

    def run(argv, data, env, fd):
        calls.append(argv)
        if argv[0].endswith("s6-svstat"):
            return b"true true" if alive[0] else b"false false"
        if "-d" in argv:
            alive[0] = False
        if "-u" in argv:
            alive[0] = True
        return b""

    monkeypatch.setattr(process, "_run", run)
    monkeypatch.setattr(process, "_processes", lambda: tuple(alive))
    service = process._Service(lock)
    service.stop()
    service.start()
    assert any("-wD" in call and "25000" in call for call in calls)
    assert any("-wU" in call and "25000" in call for call in calls)
    monkeypatch.setattr(process, "_processes", lambda: (True, False))
    with pytest.raises(UnifiOperationError):
        service.stop()
