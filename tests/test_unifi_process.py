import contextlib
import fcntl
import os
import shutil
import signal
import subprocess
import sys
import time
import traceback
from pathlib import Path

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
    (tmp_path / "123").mkdir()
    monkeypatch.setattr(
        process, "Path", lambda value: tmp_path if value == "/proc" else Path(value)
    )

    def denied(*args):
        raise PermissionError

    monkeypatch.setattr(process.os, "readlink", denied)
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
