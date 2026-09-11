"""Abrupt helper death against disposable files; not power-loss or real s6 tests."""

import json
import os
import signal
import time
from pathlib import Path

import pytest
from test_unifi_executor import install
from test_unifi_executor import platform as platform

import unifi_executor as executor
import unifi_executor_files as filesystem
from unifi_client import UnifiOperationError
from unifi_executor_files import CANONICAL, JOURNAL, JOURNAL_NEW, ROLLBACK, STAGE


def _wait_for_checkpoint_death(child, timeout_message):
    deadline = time.monotonic() + 10
    while True:
        waited, status = os.waitpid(child, os.WNOHANG)
        if waited:
            return waited, status
        if time.monotonic() >= deadline:
            os.kill(child, signal.SIGKILL)
            reap_deadline = time.monotonic() + 1
            while time.monotonic() < reap_deadline:
                waited, _ = os.waitpid(child, os.WNOHANG)
                if waited:
                    pytest.fail(timeout_message)
                time.sleep(0.01)
            pytest.fail(f"{timeout_message}; helper also resisted bounded SIGKILL reap")
        time.sleep(0.01)


@pytest.mark.parametrize(
    "point",
    [
        "before_journal",
        "initial_journal_temp",
        "quiescing",
        "after_stop",
        "during_copy",
        "after_copy",
        "during_import",
        "after_import",
        "before_stage_sync",
        "after_stage_sync",
        "after_link",
        "after_link_sync",
        "before_rename",
        "after_rename",
        "after_commit_sync",
        "before_canonical_verified",
        "canonical_verified",
        "after_start",
        "service_resumed_pending_live_verification",
    ],
)
def test_sigkill_leaves_recoverable_or_explicit_operator_state(platform, point):
    p = platform
    child = os.fork()
    if child == 0:
        # Changes are confined to this fork: no Python finally or exception
        # handler may rewrite the journal after the selected interruption.
        def die():
            os.kill(os.getpid(), signal.SIGKILL)

        def wrap(cls, name, condition, *, after):
            original = getattr(cls, name)

            def operation(self, *args, **kwargs):
                selected = condition(self, *args, **kwargs)
                if selected and not after:
                    die()
                result = original(self, *args, **kwargs)
                if selected and after:
                    die()
                return result

            setattr(cls, name, operation)

        try:
            if point in {
                "quiescing",
                "canonical_verified",
                "service_resumed_pending_live_verification",
                "before_canonical_verified",
            }:
                phase = point.removeprefix("before_")
                wrap(
                    executor.ProductionUnifiExecutor,
                    "_phase",
                    lambda self, name, **kwargs: name == phase,
                    after=not point.startswith("before_"),
                )
            elif point in {"after_stop", "after_start"}:
                wrap(
                    executor._Service,
                    point.removeprefix("after_"),
                    lambda *args: True,
                    after=True,
                )
            elif point == "before_journal":
                wrap(
                    filesystem._Files, "write_journal", lambda *args: True, after=False
                )
            elif point == "initial_journal_temp":
                wrap(
                    filesystem._Files,
                    "replace",
                    lambda self, source, target: source == JOURNAL_NEW,
                    after=False,
                )
            elif point == "during_copy":
                os.copy_file_range = lambda *args: die()
            elif point == "after_copy":
                wrap(filesystem._Files, "copy_stage", lambda *args: True, after=True)
            elif point in {"during_import", "after_import"}:
                original_run = executor._run

                def run(argv, *args):
                    if "-importcert" in argv and point == "during_import":
                        Path(argv[argv.index("-keystore") + 1]).write_bytes(b"partial")
                        die()
                    result = original_run(argv, *args)
                    if "-importcert" in argv:
                        die()
                    return result

                executor._run = run
            elif point in {"before_stage_sync", "after_stage_sync"}:
                wrap(
                    filesystem._Files,
                    "sync_file",
                    lambda self, name: name == STAGE,
                    after=point == "after_stage_sync",
                )
            elif point == "after_link":
                wrap(filesystem._Files, "link_rollback", lambda *args: True, after=True)
            elif point in {"after_link_sync", "after_commit_sync"}:
                marker = b"old" if point == "after_link_sync" else b"issued"
                wrap(
                    filesystem._Files,
                    "sync_directory",
                    lambda self: (
                        (p.root / ROLLBACK).exists()
                        and (p.root / CANONICAL).read_bytes() == marker
                    ),
                    after=True,
                )
            else:
                wrap(
                    filesystem._Files,
                    "replace",
                    lambda self, source, target: source == STAGE,
                    after=point == "after_rename",
                )
            install(p)
        except BaseException:
            os._exit(71)
        os._exit(72)
    # A deadline bounds a regression that hangs instead of reaching the kill point.
    # The fixture's fake commands do not spawn children or touch actual services.
    waited, status = _wait_for_checkpoint_death(
        child, "disposable helper did not reach interruption point"
    )
    assert os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL
    if (p.root / JOURNAL).exists():
        assert (
            json.loads((p.root / JOURNAL).read_bytes())["phase"] != "recovery_required"
        )
    if point == "initial_journal_temp":
        with pytest.raises(UnifiOperationError):
            p.adapter.recover()
        assert (p.root / JOURNAL_NEW).exists()
        assert (p.root / CANONICAL).read_bytes() == b"old"
    elif point == "before_journal":
        assert p.adapter.recover() == "no_active_transaction"
    else:
        outcome = p.adapter.recover()
        assert outcome in {"recovered_old", "service_resumed_pending_live_verification"}
        assert (p.root / CANONICAL).read_bytes() in {b"old", b"issued"}
        if outcome == "service_resumed_pending_live_verification":
            assert (p.root / ROLLBACK).read_bytes() == b"old"
        # Recovery must never repeat keytool import.
        assert all("-importcert" not in argv for argv in p.state.commands)


def test_changed_mount_device_identity_requires_operator_recovery(platform):
    p = platform
    install(p)
    journal = json.loads((p.root / JOURNAL).read_bytes())
    # Model a journal retained from a mount using different anonymous device IDs.
    for name in ("old_inode", "stage_inode"):
        journal[name][0] += 1
    (p.root / JOURNAL).write_text(json.dumps(journal))
    with pytest.raises(UnifiOperationError):
        p.adapter.recover()
    assert (p.root / CANONICAL).read_bytes() == b"issued"
    assert (p.root / ROLLBACK).read_bytes() == b"old"
    assert (p.root / JOURNAL).exists()
    assert not p.service.up


def test_old_canonical_without_rollback_recovers_without_import(platform):
    p = platform
    p.state.import_error = TimeoutError()
    with pytest.raises(UnifiOperationError):
        install(p)
    assert not (p.root / ROLLBACK).exists()
    assert p.adapter.recover() == "recovered_old"
    assert p.events.count("import") == 1


def test_corrupt_canonical_and_rollback_preserves_both_for_operator(platform):
    p = platform
    install(p)
    for name in (CANONICAL, ROLLBACK):
        (p.root / name).write_bytes(b"corrupt")
    with pytest.raises(UnifiOperationError):
        p.adapter.recover()
    assert all((p.root / name).exists() for name in (CANONICAL, ROLLBACK, JOURNAL))
    assert not p.service.up


@pytest.mark.parametrize(
    "point",
    [
        "live_verified",
        "live_verified_before_directory_sync",
        "rollback_removed",
        "rollback_cleanup_synced",
        "journal_removed",
        "journal_cleanup_synced",
    ],
)
def test_sigkill_during_live_finalisation_is_idempotently_recoverable(platform, point):
    p = platform
    install(p)
    child = os.fork()
    if child == 0:

        def die():
            os.kill(os.getpid(), signal.SIGKILL)

        original_phase = executor.ProductionUnifiExecutor._phase
        original_remove = filesystem._Files.remove
        original_sync = filesystem._Files.sync_directory

        def phase(self, name, **changes):
            result = original_phase(self, name, **changes)
            if point == "live_verified" and name == "live_verified":
                die()
            return result

        def remove(self, name):
            result = original_remove(self, name)
            if point == "rollback_removed" and name == ROLLBACK:
                die()
            if point == "journal_removed" and name == JOURNAL:
                die()
            return result

        def sync(self):
            if (
                point == "live_verified_before_directory_sync"
                and (p.root / JOURNAL).exists()
                and (p.root / ROLLBACK).exists()
                and json.loads((p.root / JOURNAL).read_bytes())["phase"]
                == "live_verified"
            ):
                die()
            result = original_sync(self)
            rollback = (p.root / ROLLBACK).exists()
            journal = (p.root / JOURNAL).exists()
            if point == "rollback_cleanup_synced" and not rollback and journal:
                die()
            if point == "journal_cleanup_synced" and not rollback and not journal:
                die()
            return result

        executor.ProductionUnifiExecutor._phase = phase
        filesystem._Files.remove = remove
        filesystem._Files.sync_directory = sync
        try:
            p.adapter.finalize_live_verification(p.plan.certificate_chain_der[0])
        except BaseException:
            os._exit(71)
        os._exit(72)

    waited, status = _wait_for_checkpoint_death(
        child, "disposable finalisation helper did not reach checkpoint"
    )
    assert waited == child
    assert os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL
    result = p.adapter.recover()
    assert result in {"renewal_finalized", "no_active_transaction"}
    assert p.adapter.recover() == "no_active_transaction"
    assert not any((p.root / name).exists() for name in (ROLLBACK, JOURNAL, STAGE))
    assert p.events.count("import") == 1
