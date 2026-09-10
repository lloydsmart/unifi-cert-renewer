"""Real filesystem transactions with generated public certificates and fake Java/s6.

Files contain harmless markers, NOT simulated PKCS12 claims. Java integration is
separate; these tests exercise inode, locking, durability order and crash recovery.
"""

import json
import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from conftest import metadata, public_pem
from cryptography import x509

import unifi_executor as executor
import unifi_executor_files as filesystem
from unifi_client import (
    PublicKeystoreState,
    UnifiClient,
    UnifiOperationError,
    prepare_certificate_import,
)
from unifi_executor_files import CANONICAL, JOURNAL, JOURNAL_NEW, ROLLBACK, STAGE


@pytest.fixture
def platform(tmp_path, monkeypatch, installation_material):
    request = installation_material.request
    plan = prepare_certificate_import(request)
    files = object.__new__(filesystem._Files)
    files.uid, files.gid = os.getuid(), os.getgid()
    files.fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    os.close(files.fd)
    events = []
    service = SimpleNamespace(up=True, keytool=False, java=False)

    def make_files(*args):
        result = object.__new__(filesystem._Files)
        result.uid, result.gid = files.uid, files.gid
        result.root = str(tmp_path)
        result.fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
        return result

    monkeypatch.setattr(executor, "_Files", make_files)
    monkeypatch.setattr(filesystem, "_ADMIN", (os.getuid(), os.getgid()))
    monkeypatch.setattr(executor, "_local_identity", lambda: (files.uid, files.gid))
    monkeypatch.setattr(executor, "_require_mutation_review", lambda: None)
    monkeypatch.setattr(
        executor,
        "_password_environment",
        lambda: {"UNIFI_KEYSTORE_PASSWORD": "synthetic-secret"},
    )

    class Service:
        def __init__(self, lock):
            self.lock = lock

        def running(self):
            return service.up

        def no_keytool(self):
            if service.keytool:
                raise UnifiOperationError("surviving child")

        def stopped(self):
            assert not service.up
            if service.java or service.keytool:
                raise UnifiOperationError("surviving writer")

        def stop(self):
            events.append("stop")
            assert (tmp_path / JOURNAL).exists()
            self.no_keytool()
            service.up = False
            self.stopped()

        def start(self):
            events.append("start")
            self.no_keytool()
            service.up = True

    monkeypatch.setattr(executor, "_Service", Service)
    state = SimpleNamespace(import_error=None, stage_state=None, commands=[])

    def run(argv, data, env, lock):
        assert env == {"UNIFI_KEYSTORE_PASSWORD": "synthetic-secret"}
        assert "synthetic-secret" not in argv
        state.commands.append(argv)
        path = Path(argv[argv.index("-keystore") + 1])
        if "-importcert" in argv:
            assert path.name == STAGE
            assert data == plan.reply_pem
            assert not service.up
            assert path.stat().st_ino != (tmp_path / CANONICAL).stat().st_ino
            events.append("import")
            path.write_bytes(b"issued")
            if state.import_error:
                raise state.import_error
            return b""
        if "-certreq" in argv:
            return request.csr_pem
        assert "-list" in argv and "-rfc" in argv
        marker = path.read_bytes()
        if marker == b"old":
            public = request.before
        elif marker == b"issued":
            public = state.stage_state or PublicKeystoreState(
                metadata(2), plan.certificate_chain_der
            )
        else:
            raise UnifiOperationError("unreadable disposable marker")
        return public.keytool_output.encode() + b"\n".join(
            public_pem(x509.load_der_x509_certificate(der))
            for der in public.certificate_chain_der
        )

    monkeypatch.setattr(executor, "_run", run)
    canonical = tmp_path / CANONICAL
    canonical.write_bytes(b"old")
    canonical.chmod(0o600)
    return SimpleNamespace(
        root=tmp_path,
        request=request,
        plan=plan,
        events=events,
        service=service,
        state=state,
        run=run,
        make_files=make_files,
        adapter=executor.ProductionUnifiExecutor(),
    )


def install(p):
    return UnifiClient(p.adapter).install_certificate(p.request)


def test_real_production_gate_has_no_enable_argument():
    with pytest.raises(UnifiOperationError, match="disabled"):
        executor._require_mutation_review()
    with pytest.raises(TypeError):
        executor.ProductionUnifiExecutor(enabled=True)
    adapter = executor.ProductionUnifiExecutor()
    with pytest.raises(UnifiOperationError, match="disabled"):
        adapter.recover()
    with pytest.raises(UnifiOperationError, match="disabled"), adapter.exclusive():
        pytest.fail("gate reached filesystem")


def test_success_uses_independent_stage_and_retains_rollback(platform):
    p = platform
    old_inode = (p.root / CANONICAL).stat().st_ino
    result = install(p)
    assert result.certificate == p.plan.issued
    assert (p.root / ROLLBACK).stat().st_ino == old_inode
    assert (p.root / CANONICAL).stat().st_ino != old_inode
    assert (p.root / CANONICAL).read_bytes() == b"issued"
    assert not (p.root / STAGE).exists()
    assert p.events == ["stop", "import", "start"]
    journal = json.loads((p.root / JOURNAL).read_bytes())
    assert journal["phase"] == "service_resumed_pending_live_verification"
    assert "synthetic-secret" not in (p.root / JOURNAL).read_text()
    assert p.adapter.recover() == "service_resumed_pending_live_verification"
    assert (p.root / ROLLBACK).exists()
    with pytest.raises(UnifiOperationError):
        install(p)
    assert p.events.count("import") == 1


def test_no_active_recovery_and_public_inspection_and_csr(platform):
    p = platform
    assert p.adapter.recover() == "no_active_transaction"
    assert p.adapter.inspect_public_state() == p.request.before
    assert p.adapter.generate_csr(p.request.policy) == p.request.csr_pem
    assert p.events == []
    assert not (p.root / JOURNAL).exists()
    with pytest.raises(UnifiOperationError):
        p.adapter.generate_csr(("/bin/sh", "-c", "id"))


@pytest.mark.parametrize(
    "change", ["missing", "symlink", "directory", "fifo", "mode", "hardlink", "owner"]
)
def test_unsafe_canonical_rejected_before_stop(platform, monkeypatch, change):
    p = platform
    path = p.root / CANONICAL
    if change in {"missing", "symlink", "directory", "fifo"}:
        path.unlink()
    if change == "symlink":
        path.symlink_to(p.root / "elsewhere")
    elif change == "directory":
        path.mkdir()
    elif change == "fifo":
        os.mkfifo(path, 0o600)
    elif change == "mode":
        path.chmod(0o644)
    elif change == "hardlink":
        os.link(path, p.root / "uncontrolled")
    elif change == "owner":
        original = p.make_files

        def wrong_owner(*args):
            result = original(*args)
            result.uid += 1
            return result

        monkeypatch.setattr(executor, "_Files", wrong_owner)
    with pytest.raises(UnifiOperationError):
        install(p)
    assert p.events == []


@pytest.mark.parametrize(
    "error", [RuntimeError("synthetic-secret"), TimeoutError(), KeyboardInterrupt()]
)
def test_import_failure_never_commits_and_requires_fresh_recovery(platform, error):
    p = platform
    old = (p.root / CANONICAL).stat().st_ino
    p.state.import_error = error
    with pytest.raises((UnifiOperationError, KeyboardInterrupt)) as raised:
        install(p)
    assert "synthetic-secret" not in str(raised.value)
    assert (p.root / CANONICAL).stat().st_ino == old
    assert (p.root / CANONICAL).read_bytes() == b"old"
    assert not p.service.up
    assert p.adapter.recover() == "recovered_old"
    assert p.service.up
    assert not (p.root / JOURNAL).exists()
    assert not (p.root / STAGE).exists()
    assert p.events.count("import") == 1


@pytest.mark.parametrize(
    "change", ["leaf", "spki", "chain", "alias", "entry", "provider", "length"]
)
def test_stage_mismatch_preserves_canonical(platform, installation_material, change):
    p = platform
    public = PublicKeystoreState(metadata(2), p.plan.certificate_chain_der)
    if change == "leaf":
        public = replace(
            public,
            certificate_chain_der=(
                p.request.before.certificate_chain_der[0],
                p.plan.certificate_chain_der[1],
            ),
        )
    elif change == "spki":
        public = replace(
            public,
            certificate_chain_der=(
                p.plan.certificate_chain_der[1],
                p.plan.certificate_chain_der[1],
            ),
        )
    elif change == "chain":
        public = replace(
            public, certificate_chain_der=tuple(reversed(public.certificate_chain_der))
        )
    else:
        old, new = {
            "alias": ("unifi", "other"),
            "entry": ("PrivateKeyEntry", "trustedCertEntry"),
            "provider": ("SUN", "OTHER"),
            "length": ("length: 2", "length: 3"),
        }[change]
        public = replace(public, keytool_output=public.keytool_output.replace(old, new))
    p.state.stage_state = public
    with pytest.raises(UnifiOperationError):
        install(p)
    assert (p.root / CANONICAL).read_bytes() == b"old"
    assert p.adapter.recover() == "recovered_old"


@pytest.mark.parametrize(
    "method",
    [
        "copy_stage",
        "sync_file",
        "link_rollback",
        "replace",
        "sync_directory",
        "write_journal",
    ],
)
@pytest.mark.parametrize("after", [False, True])
def test_filesystem_faults_recover_conservatively(platform, monkeypatch, method, after):
    p = platform
    original = getattr(filesystem._Files, method)
    failed = False

    def fail_once(self, *args, **kwargs):
        nonlocal failed
        # Target a transaction transition after durable quiescence, not lock setup.
        eligible = (p.root / JOURNAL).exists() and not p.service.up
        if method == "replace":
            eligible &= args == (STAGE, CANONICAL)
        if not failed and eligible:
            failed = True
            if after:
                original(self, *args, **kwargs)
            raise OSError("synthetic-secret")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(filesystem._Files, method, fail_once)
    with pytest.raises(UnifiOperationError):
        install(p)
    assert failed
    outcome = p.adapter.recover()
    assert outcome in {"recovered_old", "service_resumed_pending_live_verification"}
    assert p.service.up
    assert p.events.count("import") <= 1


@pytest.mark.parametrize(
    "phase",
    [
        "quiescing",
        "quiesced",
        "staging",
        "staged_validated",
        "rollback_durable",
        "commit_possible",
        "committed",
        "canonical_verified",
        "service_resumed_pending_live_verification",
    ],
)
def test_crash_at_every_durable_phase(platform, monkeypatch, phase):
    p = platform
    original = executor.ProductionUnifiExecutor._phase
    crashed = False

    def crash(self, name, **changes):
        nonlocal crashed
        original(self, name, **changes)
        if name == phase and not crashed:
            crashed = True
            raise KeyboardInterrupt

    monkeypatch.setattr(executor.ProductionUnifiExecutor, "_phase", crash)
    with pytest.raises(KeyboardInterrupt):
        install(p)
    assert crashed
    # Simulate a new executor instance. No cached Python state is reused.
    p.adapter = executor.ProductionUnifiExecutor()
    outcome = p.adapter.recover()
    assert outcome in {"recovered_old", "service_resumed_pending_live_verification"}
    assert p.service.up
    assert p.events.count("import") <= 1


def test_post_commit_corruption_restores_original_inode(platform):
    p = platform
    old = (p.root / CANONICAL).stat().st_ino
    install(p)
    (p.root / CANONICAL).write_bytes(b"corrupted")
    assert p.adapter.recover() == "recovered_old"
    assert (p.root / CANONICAL).stat().st_ino == old
    assert (p.root / CANONICAL).read_bytes() == b"old"
    assert not (p.root / ROLLBACK).exists()
    assert p.service.up


@pytest.mark.parametrize("target", [CANONICAL, ROLLBACK])
@pytest.mark.parametrize(
    "change", ["replaced", "unexpected", "symlink", "mode", "missing"]
)
def test_unexpected_recovery_state_fails_closed(platform, target, change):
    p = platform
    install(p)
    path = p.root / target
    if change == "replaced":
        os.link(path, p.root / "retain-test-inode")
    if change in {"replaced", "symlink", "missing"}:
        path.unlink()
    if change == "replaced":
        path.write_bytes(b"old")
        path.chmod(0o600)
    elif change == "unexpected":
        path.write_bytes(b"old" if target == CANONICAL else b"issued")
    elif change == "symlink":
        path.symlink_to(p.root / "other")
    elif change == "mode":
        path.chmod(0o644)
    with pytest.raises(UnifiOperationError):
        p.adapter.recover()
    assert (p.root / JOURNAL).exists()
    assert not p.service.up
    assert p.events.count("import") == 1


@pytest.mark.parametrize("point", ["stop", "start", "java", "keytool"])
def test_service_failure_never_returns_success(platform, monkeypatch, point):
    p = platform
    if point in {"java", "keytool"}:
        setattr(p.service, point, True)
    else:

        def fail(self):
            raise TimeoutError("synthetic-secret")

        monkeypatch.setattr(executor._Service, point, fail)
    with pytest.raises(UnifiOperationError):
        install(p)
    assert p.events.count("import") == (1 if point == "start" else 0)


def test_stale_state_after_stop_is_rejected(platform, monkeypatch):
    p = platform
    original = executor._Service.stop

    def stop(self):
        original(self)
        path = p.root / CANONICAL
        path.unlink()
        path.write_bytes(b"old")
        path.chmod(0o600)

    monkeypatch.setattr(executor._Service, "stop", stop)
    with pytest.raises(UnifiOperationError):
        install(p)
    assert "import" not in p.events


def test_collector_rejects_change_during_java_read(platform, monkeypatch):
    p = platform

    def changed(*args):
        output = p.run(*args)
        (p.root / CANONICAL).write_bytes(b"old updated")
        return output

    monkeypatch.setattr(executor, "_run", changed)
    with pytest.raises(UnifiOperationError):
        p.adapter.inspect_public_state()


def test_dataclass_and_public_api_cannot_select_command_or_target(platform):
    p = platform
    assert not hasattr(p.plan, "argv")
    for value in (p.plan, p.plan.reply_pem, ("/bin/sh", "-c", "id")):
        with pytest.raises(UnifiOperationError), p.adapter.exclusive():
            p.adapter.import_certificate_reply(value, expected_before=p.request.before)
        assert p.adapter.recover() == "recovered_old"
    assert "import" not in p.events
    with pytest.raises(UnifiOperationError):
        p.adapter.import_certificate_reply(p.request, expected_before=p.request.before)


def test_cooperating_writer_lock_excludes_another_executor(platform):
    p = platform
    with p.adapter._locked(), pytest.raises(UnifiOperationError):
        executor.ProductionUnifiExecutor().inspect_public_state()
    assert p.adapter.inspect_public_state() == p.request.before


@pytest.mark.parametrize(
    "data", [b"x" * (1024 * 1024 + 1), b"invalid", b"Alias name: other\n", b"\xff"]
)
def test_collector_is_bounded_and_rejects_malformed_output(data):
    with pytest.raises((ValueError, UnicodeError)):
        executor._parse_collection(data)


def test_collection_is_single_read_and_excludes_unrelated_alias(platform):
    p = platform
    blob = p.request.before.keytool_output.encode() + p.request.issued_certificate
    blob += (
        b"\nAlias name: unrelated\nEntry type: trustedCertEntry\n"
        + p.request.trusted_ca_data
    )
    state = executor._parse_collection(blob)
    assert len(state.certificate_chain_der) == 1
    assert "unrelated" not in state.keytool_output
    p.adapter.inspect_public_state()
    assert len(p.state.commands) == 1


@pytest.mark.parametrize(
    "change",
    [
        "extra",
        "phase",
        "boolean",
        "digest",
        "inode",
        "version",
        "duplicate",
        "oversized",
    ],
)
def test_invalid_journal_blocks_recovery_before_service_stop(platform, change):
    p = platform
    install(p)
    journal = json.loads((p.root / JOURNAL).read_bytes())
    if change == "extra":
        journal["path"] = "/tmp/other"
    elif change == "phase":
        journal["phase"] = "unknown"
    elif change == "boolean":
        journal["resume"] = "true"
    elif change == "digest":
        journal["old"]["spki"] = "invalid"
    elif change == "inode":
        journal["old_inode"] = [True, 1]
    elif change == "version":
        journal["version"] = True
    data = json.dumps(journal).encode()
    if change == "duplicate":
        data = b'{"version":1,"version":1}'
    if change == "oversized":
        data = b"x" * 20000
    (p.root / JOURNAL).write_bytes(data)
    before = p.events.copy()
    with pytest.raises(UnifiOperationError):
        p.adapter.recover()
    assert p.events == before


def test_initially_down_service_stays_down(platform):
    p = platform
    p.service.up = False
    install(p)
    assert "start" not in p.events
    p.adapter.recover()
    assert "start" not in p.events


def test_internal_file_operations_reject_arbitrary_names(platform):
    files = platform.make_files()
    try:
        for path in ("/config/data/keystore", "../keystore", "anything"):
            with pytest.raises(UnifiOperationError):
                files.status(path)
        with pytest.raises(UnifiOperationError):
            files.replace(CANONICAL, STAGE)
        with pytest.raises(UnifiOperationError):
            files.remove(CANONICAL)
    finally:
        files.close()


@pytest.mark.parametrize(
    "transition",
    [
        "stage_sync",
        "before_commit_sync",
        "after_commit_sync",
        "commit_journal",
        "canonical_inspection",
        "resume_change",
    ],
)
def test_security_significant_failure_points(platform, monkeypatch, transition):
    p = platform
    sync_file = filesystem._Files.sync_file
    sync_dir = filesystem._Files.sync_directory
    write_journal = filesystem._Files.write_journal
    collect = executor.ProductionUnifiExecutor._collect
    start = executor._Service.start
    failed = False

    def fail_if(condition):
        nonlocal failed
        if condition and not failed:
            failed = True
            raise OSError("injected failure")

    def file_sync(self, name):
        fail_if(transition == "stage_sync" and name == STAGE)
        return sync_file(self, name)

    def directory_sync(self):
        canonical = p.root / CANONICAL
        fail_if(
            transition == "before_commit_sync"
            and (p.root / ROLLBACK).exists()
            and canonical.read_bytes() == b"old"
        )
        fail_if(
            transition == "after_commit_sync" and canonical.read_bytes() == b"issued"
        )
        return sync_dir(self)

    def journal(self, value):
        fail_if(transition == "commit_journal" and value["phase"] == "committed")
        return write_journal(self, value)

    def inspect(self, name):
        fail_if(
            transition == "canonical_inspection"
            and name == CANONICAL
            and (p.root / name).read_bytes() == b"issued"
        )
        return collect(self, name)

    def resume(self):
        nonlocal failed
        start(self)
        if transition == "resume_change" and not failed:
            failed = True
            (p.root / CANONICAL).write_bytes(b"corrupt")

    monkeypatch.setattr(filesystem._Files, "sync_file", file_sync)
    monkeypatch.setattr(filesystem._Files, "sync_directory", directory_sync)
    monkeypatch.setattr(filesystem._Files, "write_journal", journal)
    monkeypatch.setattr(executor.ProductionUnifiExecutor, "_collect", inspect)
    monkeypatch.setattr(executor._Service, "start", resume)
    with pytest.raises(UnifiOperationError):
        install(p)
    assert failed
    result = p.adapter.recover()
    assert result in {"recovered_old", "service_resumed_pending_live_verification"}
    assert p.events.count("import") == 1


def test_durability_order_and_atomic_namespace_without_gap(platform, monkeypatch):
    p = platform
    observed = []
    for name in ("sync_file", "link_rollback", "sync_directory", "replace"):
        original = getattr(filesystem._Files, name)

        def trace(self, *args, _name=name, _original=original):
            assert (p.root / CANONICAL).exists()
            result = _original(self, *args)
            assert (p.root / CANONICAL).exists()
            observed.append((_name, args))
            return result

        monkeypatch.setattr(filesystem._Files, name, trace)
    install(p)
    link = observed.index(("link_rollback", ()))
    commit = observed.index(("replace", (STAGE, CANONICAL)))
    assert observed.index(("sync_file", (STAGE,))) < link < commit
    assert ("sync_directory", ()) in observed[link + 1 : commit]
    assert observed[commit + 1] == ("sync_directory", ())


def test_directory_replacement_is_detected(platform):
    p = platform
    files = p.make_files()
    moved = p.root.with_name(p.root.name + "-old")
    try:
        p.root.rename(moved)
        p.root.mkdir()
        with pytest.raises(UnifiOperationError, match="directory identity"):
            files.status(CANONICAL)
    finally:
        files.close()
        p.root.rmdir()
        moved.rename(p.root)


def test_surviving_writer_retains_lock(platform):
    p = platform
    p.service.java = True
    with pytest.raises(UnifiOperationError):
        install(p)
    assert p.adapter._lock is not None
    with pytest.raises(UnifiOperationError):
        executor.ProductionUnifiExecutor().recover()
    # Model operator stopping the unsafe helper; do not leak the test descriptor.
    os.close(p.adapter._lock)
    p.adapter._files.close()


@pytest.mark.parametrize("point", [STAGE, ROLLBACK, JOURNAL_NEW, JOURNAL])
def test_interrupted_recovery_cleanup_resumes_without_retry(
    platform, monkeypatch, point
):
    p = platform
    p.state.import_error = TimeoutError()
    with pytest.raises(UnifiOperationError):
        install(p)
    original = filesystem._Files.remove
    failed = False

    def interrupted(self, name):
        nonlocal failed
        # Fail immediately before any cleanup step, including currently absent
        # entries, after service restoration and recovered_old were persisted.
        if name == point and not failed and p.service.up:
            failed = True
            raise OSError
        return original(self, name)

    monkeypatch.setattr(filesystem._Files, "remove", interrupted)
    with pytest.raises(UnifiOperationError):
        p.adapter.recover()
    assert p.adapter.recover() == "recovered_old"
    assert p.events.count("import") == 1


def test_fresh_structural_stage_check_precedes_import(platform, monkeypatch):
    p = platform
    original = filesystem._Files.copy_stage

    def corrupt(self):
        original(self)
        (p.root / STAGE).write_bytes(b"corrupt")

    monkeypatch.setattr(filesystem._Files, "copy_stage", corrupt)
    with pytest.raises(UnifiOperationError):
        install(p)
    assert "import" not in p.events
    assert p.adapter.recover() == "recovered_old"


@pytest.mark.parametrize("operation", ["-importcert", "-genkeypair", "-delete"])
def test_public_surface_has_no_generic_command_dispatch(platform, operation):
    p = platform
    with pytest.raises((TypeError, UnifiOperationError)):
        p.adapter.generate_csr(
            ("/usr/bin/keytool", operation, "-keystore", "/config/data/keystore")
        )
    assert p.state.commands == []


@pytest.mark.parametrize("point", ["replace", "sync_directory", "write_journal"])
def test_crash_during_atomic_recovery_can_be_recovered_again(
    platform, monkeypatch, point
):
    p = platform
    install(p)
    old_inode = (p.root / ROLLBACK).stat().st_ino
    (p.root / CANONICAL).write_bytes(b"corrupt")
    original = getattr(filesystem._Files, point)
    failed = False

    def crash(self, *args):
        nonlocal failed
        result = original(self, *args)
        if not failed and (p.root / CANONICAL).stat().st_ino == old_inode:
            failed = True
            raise KeyboardInterrupt
        return result

    monkeypatch.setattr(filesystem._Files, point, crash)
    with pytest.raises(KeyboardInterrupt):
        p.adapter.recover()
    assert p.adapter.recover() == "recovered_old"
    assert (p.root / CANONICAL).stat().st_ino == old_inode
    assert p.events.count("import") == 1


def test_password_loaded_only_from_fixed_local_secret(monkeypatch):
    import io

    calls = []

    def secret(name, **kwargs):
        calls.append((name, kwargs))
        return io.BytesIO(b"synthetic-local-password\n")

    monkeypatch.setattr(executor, "open_secure_file", secret)
    result = executor._password_environment()
    assert result["UNIFI_KEYSTORE_PASSWORD"] == "synthetic-local-password"
    assert calls == [
        (
            "unifi-keystore-password",
            {"source_name": "UniFi password", "require_private": True},
        )
    ]


@pytest.mark.parametrize(
    "data", [b"", b"\n", b"x" * 4097, b"bad\x00value", b"bad\nvalue", b"\xff"]
)
def test_password_file_is_bounded_and_validated(monkeypatch, data):
    import io

    monkeypatch.setattr(
        executor, "open_secure_file", lambda *args, **kwargs: io.BytesIO(data)
    )
    with pytest.raises(ValueError):
        executor._password_environment()


def test_sparse_oversized_canonical_rejected(platform):
    p = platform
    with (p.root / CANONICAL).open("r+b") as stream:
        stream.truncate(filesystem.MAX_STORE + 1)
    with pytest.raises(UnifiOperationError):
        install(p)
    assert p.events == []


def test_real_directory_opener_and_symlink_rejection(tmp_path, monkeypatch):
    # Substitute only the root anchor; all component opens and no-follow checks
    # use real Linux descriptors in a disposable private directory.
    original = os.open

    def anchored(path, flags, *args, **kwargs):
        return original(str(tmp_path) if path == "/" else path, flags, *args, **kwargs)

    monkeypatch.setattr(filesystem.os, "open", anchored)
    target = tmp_path / "data"
    target.mkdir(mode=0o700)
    monkeypatch.setattr(filesystem, "_filesystem", lambda fd: None)
    monkeypatch.setattr(filesystem, "_ROOT", "/data")
    files = filesystem._Files(os.getuid(), os.getgid())
    files.close()
    (tmp_path / "alias").symlink_to(target, target_is_directory=True)
    monkeypatch.setattr(filesystem, "_ROOT", "/alias")
    with pytest.raises(OSError):
        filesystem._Files(os.getuid(), os.getgid())
    monkeypatch.setattr(filesystem, "_ROOT", "/data")
    target.chmod(0o777)
    with pytest.raises(UnifiOperationError):
        filesystem._Files(os.getuid(), os.getgid())


@pytest.mark.parametrize("kind", ["btrfs", "overlay", "ext4"])
def test_filesystem_gate_requires_evidenced_btrfs(platform, monkeypatch, kind):
    import io

    files = platform.make_files()
    try:
        dev = os.fstat(files.fd).st_dev
        line = f"1 2 {os.major(dev)}:{os.minor(dev)} / /config/data rw - {kind} source rw\n"
        monkeypatch.setattr("builtins.open", lambda *args, **kwargs: io.StringIO(line))
        if kind == "btrfs":
            filesystem._filesystem(files.fd)
        else:
            with pytest.raises(UnifiOperationError):
                filesystem._filesystem(files.fd)
    finally:
        files.close()


def test_local_identity_requires_reviewed_root_and_abc_baseline(monkeypatch):
    monkeypatch.setattr(executor.os, "geteuid", lambda: 1000)
    with pytest.raises(UnifiOperationError):
        executor._local_identity()
    monkeypatch.setattr(executor.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        executor.pwd, "getpwnam", lambda name: SimpleNamespace(pw_uid=1001, pw_gid=1000)
    )
    with pytest.raises(UnifiOperationError):
        executor._local_identity()
    monkeypatch.setattr(
        executor.pwd, "getpwnam", lambda name: SimpleNamespace(pw_uid=1000, pw_gid=1000)
    )
    assert executor._local_identity() == (1000, 1000)


def test_fifo_lock_rejected_without_blocking(platform):
    p = platform
    os.mkfifo(p.root / filesystem.LOCK, 0o600)
    # Run the real acquisition in a separate process so a missing O_NONBLOCK
    # fails within the deadline rather than hanging the complete test suite.
    script = """
import os
import sys
import unifi_executor as executor
from unifi_executor_files import _Files
from unifi_client import UnifiOperationError

def files(*args):
    result = object.__new__(_Files)
    result.uid, result.gid = os.getuid(), os.getgid()
    result.root = sys.argv[1]
    result.fd = os.open(result.root, os.O_RDONLY | os.O_DIRECTORY)
    return result

executor._Files = files
executor._local_identity = lambda: (os.getuid(), os.getgid())
try:
    executor.ProductionUnifiExecutor().inspect_public_state()
except UnifiOperationError:
    sys.exit(0)
sys.exit(1)
"""
    result = subprocess.run(
        [sys.executable, "-c", script, str(p.root)],
        env={**os.environ, "PYTHONPATH": str(Path(executor.__file__).parent)},
        capture_output=True,
        timeout=5,
        check=False,
    )
    assert result.returncode == 0
