"""Tests for the fixed production IPC and startup-recovery boundary."""

import json
import os
import stat
import struct
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest
from conftest import metadata

import unifi_executor_files as executor_files
import unifi_executor_service as service
from unifi_client import PublicKeystoreState, UnifiClient, UnifiOperationError


class FakeExecutor:
    def __init__(self, material, *, failure=None):
        self.request = material.request
        self.plan = service.prepare_certificate_import(self.request)
        self.state = self.request.before
        self.failure = failure
        self.events = []
        self.private_marker = "DO-NOT-RETURN-private-password"

    def _fail(self):
        if self.failure:
            raise UnifiOperationError(f"failure {self.private_marker}")

    @contextmanager
    def exclusive(self):
        self.events.append("exclusive-enter")
        try:
            yield
        finally:
            self.events.append("exclusive-exit")

    def inspect_public_state(self):
        self._fail()
        self.events.append("inspect")
        return self.state

    def generate_csr(self, policy):
        self._fail()
        assert policy == self.request.policy
        self.events.append("generate_csr")
        return self.request.csr_pem

    def import_certificate_reply(self, request, *, expected_before):
        self._fail()
        assert request == self.request
        assert expected_before == self.state
        self.events.append("install")
        self.state = PublicKeystoreState(metadata(2), self.plan.certificate_chain_der)
        return 0

    def recover(self):
        self._fail()
        self.events.append("recover")
        return "no_active_transaction"

    def finalize_live_verification(self, expected_leaf_der):
        self._fail()
        assert expected_leaf_der == self.plan.certificate_chain_der[0]
        self.events.append("finalize")
        return "renewal_finalized"


@pytest.fixture
def protocol(installation_material):
    executor = FakeExecutor(installation_material)
    return executor, service._ProtocolHandler(lambda: executor)


def test_each_required_semantic_operation_is_available(protocol):
    executor, handler = protocol
    request = executor.request

    inspected = handler.dispatch(service._request("inspect", {}))
    assert service._decode_state(inspected["state"]) == request.before

    generated = handler.dispatch(
        service._request(
            "generate_csr", {"policy": service._encode_policy(request.policy)}
        )
    )
    assert service._binary(generated["csr_pem"]) == request.csr_pem

    installed = handler.dispatch(
        service._request(
            "install", {"request": service._encode_import_request(request)}
        )
    )
    assert service._decode_state(installed["state"]).certificate_chain_der == (
        executor.plan.certificate_chain_der
    )

    assert handler.dispatch(service._request("recover", {})) == {
        "outcome": "no_active_transaction"
    }
    finalized = handler.dispatch(
        service._request(
            "finalize",
            {
                "expected_leaf_der": service._encode_binary(
                    executor.plan.certificate_chain_der[0]
                )
            },
        )
    )
    assert finalized == {"outcome": "renewal_finalized"}
    assert "install" in executor.events


def test_renewer_side_boundary_preserves_existing_application_semantics(
    protocol, monkeypatch
):
    executor, handler = protocol
    boundary = service.SocketUnifiExecutionBoundary()
    monkeypatch.setattr(
        boundary,
        "_call",
        lambda operation, arguments: handler.dispatch(
            service._request(operation, arguments)
        ),
    )
    client = UnifiClient(boundary)
    assert client.inspect_current(executor.request.policy) == executor.request.before
    assert client.request_csr(executor.request.policy) == executor.request.csr_pem
    installed = client.install_certificate(executor.request)
    assert installed.certificate == executor.plan.issued
    client.finalize_live_verification(executor.plan.certificate_chain_der[0])
    assert executor.events[-1] == "finalize"


@pytest.mark.parametrize(
    "payload",
    [
        {"version": 1, "operation": "run", "arguments": {}},
        {"version": 1, "operation": "inspect", "arguments": {"path": "/tmp/x"}},
        {
            "version": 1,
            "operation": "recover",
            "arguments": {"argv": ["/bin/sh"]},
        },
        {
            "version": 1,
            "operation": "finalize",
            "arguments": {"success": True},
        },
    ],
)
def test_unsupported_or_command_or_path_shaped_requests_are_rejected(protocol, payload):
    _, handler = protocol
    with pytest.raises((ValueError, KeyError)):
        handler.dispatch(payload)


def test_policy_cannot_select_alias_service_executable_or_path(protocol):
    executor, handler = protocol
    policy = service._encode_policy(executor.request.policy)
    for field, value in {
        "alias": "other",
        "service": "other",
        "executable": "/bin/sh",
        "keystore": "/tmp/other",
    }.items():
        with pytest.raises(ValueError):
            handler.dispatch(
                service._request("generate_csr", {"policy": {**policy, field: value}})
            )


def _round_trip(handler, payload):
    class MemoryConnection:
        def __init__(self, incoming=b""):
            self.incoming = bytearray(incoming)
            self.outgoing = bytearray()

        def settimeout(self, timeout):
            assert 0 < timeout <= service.SOCKET_TIMEOUT_SECONDS

        def recv(self, length):
            result = self.incoming[:length]
            del self.incoming[:length]
            return bytes(result)

        def sendall(self, data):
            self.outgoing.extend(data)

    connection = MemoryConnection(payload)
    handler.handle(connection)
    return service._read_message(MemoryConnection(connection.outgoing))


class Connection:
    def __init__(self, incoming, *, chunk_size=None, send_error=None):
        self.incoming = bytearray(incoming)
        self.chunk_size = chunk_size
        self.send_error = send_error
        self.outgoing = bytearray()
        self.closed = False
        self.timeouts = []

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.closed = True

    def settimeout(self, timeout):
        self.timeouts.append(timeout)

    def recv(self, length):
        if self.chunk_size is not None:
            length = min(length, self.chunk_size)
        result = self.incoming[:length]
        del self.incoming[:length]
        return bytes(result)

    def sendall(self, data):
        if self.send_error is not None:
            raise self.send_error
        self.outgoing.extend(data)


def framed(request):
    data = json.dumps(request).encode("ascii")
    return struct.pack("!I", len(data)) + data


def test_absolute_request_deadline_stops_trickle_and_next_client_succeeds(
    protocol, monkeypatch
):
    _, handler = protocol

    class Clock:
        value = 0.0

        def __call__(self):
            self.value += 0.9
            return self.value

    monkeypatch.setattr(service, "REQUEST_READ_TIMEOUT_SECONDS", 3.0)
    monkeypatch.setattr(service, "_monotonic", Clock())
    slow = Connection(framed(service._request("inspect", {})), chunk_size=1)
    service._serve_client(handler, slow)
    assert slow.closed
    assert len(slow.incoming) > 0
    assert slow.timeouts == sorted(slow.timeouts, reverse=True)

    monkeypatch.setattr(service, "_monotonic", lambda: 0.0)
    valid = Connection(framed(service._request("inspect", {})))
    service._serve_client(handler, valid)
    assert valid.closed
    response = service._read_message(Connection(valid.outgoing), deadline=1.0)
    assert response["ok"] is True


def test_maximum_sized_valid_frame_is_accepted(monkeypatch):
    monkeypatch.setattr(service, "_monotonic", lambda: 0.0)
    body = json.dumps(service._request("inspect", {})).encode("ascii")
    body += b" " * (service.MAX_MESSAGE_BYTES - len(body))
    connection = Connection(struct.pack("!I", len(body)) + body)
    message = service._read_message(connection, deadline=1.0)
    assert service._decode_envelope(message) == ("inspect", {})


def test_disconnect_before_complete_request_is_contained_and_connection_closes(
    protocol, monkeypatch
):
    _, handler = protocol
    monkeypatch.setattr(service, "_monotonic", lambda: 0.0)
    disconnected = Connection(
        struct.pack("!I", 50) + b"{", send_error=BrokenPipeError()
    )
    service._serve_client(handler, disconnected)
    assert disconnected.closed

    valid = Connection(framed(service._request("inspect", {})))
    service._serve_client(handler, valid)
    assert service._read_message(Connection(valid.outgoing), deadline=1.0)["ok"] is True


@pytest.mark.parametrize(
    "failure", [BrokenPipeError(), ConnectionResetError(), service.socket.timeout()]
)
def test_response_transport_failures_are_connection_local(
    protocol, monkeypatch, failure
):
    _, handler = protocol
    monkeypatch.setattr(service, "_monotonic", lambda: 0.0)
    disconnected = Connection(
        framed(service._request("inspect", {})), send_error=failure
    )
    service._serve_client(handler, disconnected)
    assert disconnected.closed

    valid = Connection(framed(service._request("inspect", {})))
    service._serve_client(handler, valid)
    assert service._read_message(Connection(valid.outgoing), deadline=1.0)["ok"] is True


@pytest.mark.parametrize("operation", ["inspect", "install", "recover", "finalize"])
def test_disconnect_after_operation_does_not_cancel_it_or_stop_server(
    protocol, monkeypatch, operation
):
    executor, handler = protocol
    monkeypatch.setattr(service, "_monotonic", lambda: 0.0)
    arguments = {
        "inspect": {},
        "install": {"request": service._encode_import_request(executor.request)},
        "recover": {},
        "finalize": {
            "expected_leaf_der": service._encode_binary(
                executor.plan.certificate_chain_der[0]
            )
        },
    }[operation]
    disconnected = Connection(
        framed(service._request(operation, arguments)), send_error=BrokenPipeError()
    )
    service._serve_client(handler, disconnected)
    assert disconnected.closed
    expected_event = "install" if operation == "install" else operation
    assert expected_event in executor.events

    valid = Connection(framed(service._request("inspect", {})))
    service._serve_client(handler, valid)
    assert service._read_message(Connection(valid.outgoing), deadline=1.0)["ok"] is True


def test_malformed_and_oversized_messages_get_bounded_generic_error(protocol):
    _, handler = protocol
    duplicate = b'{"version":1,"version":1,"operation":"inspect","arguments":{}}'
    for payload in (
        struct.pack("!I", service.MAX_MESSAGE_BYTES + 1),
        struct.pack("!I", 1) + b"{",
        struct.pack("!I", 13) + b'{"version":1',
        struct.pack("!I", len(duplicate)) + duplicate,
    ):
        response = _round_trip(handler, payload)
        assert response == {
            "version": 1,
            "ok": False,
            "error": "executor_operation_failed",
        }
        assert len(json.dumps(response)) < 128


def test_protocol_version_type_is_strict(protocol):
    _, handler = protocol
    with pytest.raises(ValueError):
        handler.dispatch({"version": True, "operation": "inspect", "arguments": {}})


@pytest.mark.parametrize("version", [True, 1.0])
def test_response_protocol_version_type_is_strict(version):
    with pytest.raises(ValueError):
        service._decode_response(
            {"version": version, "ok": True, "result": {"state": {}}}
        )


def test_executor_failure_does_not_return_private_state_or_diagnostics(
    installation_material,
):
    executor = FakeExecutor(installation_material, failure=True)
    handler = service._ProtocolHandler(lambda: executor)
    request = json.dumps(service._request("inspect", {})).encode()
    response = _round_trip(handler, struct.pack("!I", len(request)) + request)
    rendered = json.dumps(response)
    assert response["ok"] is False
    assert executor.private_marker not in rendered
    assert "password" not in rendered


def test_response_contains_only_public_installation_data(protocol):
    executor, handler = protocol
    response = handler.dispatch(
        service._request(
            "install", {"request": service._encode_import_request(executor.request)}
        )
    )
    rendered = json.dumps(response)
    assert executor.private_marker not in rendered
    assert "/config/data/keystore" not in rendered
    assert "password" not in rendered.lower()


def test_startup_entrypoint_uses_non_resuming_recovery(monkeypatch):
    calls = []

    class StartupExecutor:
        def recover(self, *, startup=False):
            calls.append(startup)
            return "no_active_transaction"

    monkeypatch.setattr(service, "ProductionUnifiExecutor", StartupExecutor)
    monkeypatch.setattr(service, "_startup_data_directory_absent", lambda: False)
    monkeypatch.setattr(
        service, "secure_after_linuxserver_init", lambda: calls.append("secure")
    )
    assert service.recover_startup() == "no_active_transaction"
    assert calls == ["secure", True]


def test_new_empty_config_is_left_for_linuxserver_initialization(monkeypatch):
    monkeypatch.setattr(service, "_startup_data_directory_absent", lambda: True)
    monkeypatch.setattr(
        service,
        "ProductionUnifiExecutor",
        lambda: pytest.fail(
            "executor must not require a not-yet-created data directory"
        ),
    )
    assert service.recover_startup() == "no_active_transaction"


def test_post_init_entrypoint_rechecks_recovery_before_success(monkeypatch, capsys):
    calls = []
    monkeypatch.setattr(
        service,
        "recover_startup",
        lambda: calls.append("secure-and-recover") or "no_active_transaction",
    )
    assert service.main(["secure-after-init"]) == 0
    assert calls == ["secure-and-recover"]
    assert "recovery recheck: no_active_transaction" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("argument", "diagnostic"),
    [
        ("recover-startup", "startup recovery failed closed"),
        ("secure-after-init", "post-init state check failed closed"),
    ],
)
def test_startup_failures_emit_bounded_operator_diagnostic(
    monkeypatch, capsys, argument, diagnostic
):
    marker = "DO-NOT-REFLECT-private-password"

    def fail():
        raise UnifiOperationError(marker)

    monkeypatch.setattr(
        service,
        "recover_startup"
        if argument == "recover-startup"
        else "secure_after_linuxserver_init",
        fail,
    )
    assert service.main([argument]) == 1
    error = capsys.readouterr().err
    assert diagnostic in error
    assert "operator review required" in error
    assert marker not in error
    assert len(error) < 160


def test_s6_dependency_graph_orders_recovery_before_init_and_java():
    root = Path("deployment/unifi/root/etc/s6-overlay/s6-rc.d")
    recovery = "init-unifi-cert-renewer-recovery"
    secure = "init-unifi-cert-renewer-secure-state"
    assert (root / recovery / "dependencies.d/init-config").is_file()
    assert (
        root / "init-unifi-network-application-config/dependencies.d" / recovery
    ).is_file()
    assert (root / "svc-unifi-network-application/dependencies.d" / recovery).is_file()
    assert (root / "user/contents.d" / recovery).is_file()
    assert (
        root / secure / "dependencies.d/init-unifi-network-application-config"
    ).is_file()
    assert (root / "svc-unifi-network-application/dependencies.d" / secure).is_file()
    assert (root / "svc-unifi-cert-renewer-executor/dependencies.d" / secure).is_file()
    assert (root / "user/contents.d" / secure).is_file()


def test_post_init_hook_resecures_only_fixed_admin_files(tmp_path, monkeypatch):
    root = tmp_path / "config/data"
    root.mkdir(parents=True, mode=0o700)
    path = root / service.LOCK
    path.write_bytes(b"")
    path.chmod(0o600)

    original_open = os.open

    def anchored(path, flags, *args, **kwargs):
        return original_open(
            str(tmp_path) if path == "/" else path, flags, *args, **kwargs
        )

    ownership = []
    monkeypatch.setattr(service.os, "open", anchored)
    monkeypatch.setattr(service, "_local_identity", lambda: (os.getuid(), os.getgid()))
    monkeypatch.setattr(
        service.os, "fchown", lambda fd, uid, gid: ownership.append((uid, gid))
    )
    assert service.secure_after_linuxserver_init() == "executor_state_secured"
    assert ownership == [(0, 0)]
    assert [item.name for item in root.iterdir()] == [service.LOCK]


def pending_normalization_state(root):
    canonical = root / service.CANONICAL
    canonical.write_bytes(b"public-test-keystore-placeholder")
    canonical.chmod(0o600)
    identity = canonical.stat()
    journal = {
        "version": 1,
        "transaction": "a" * 32,
        "phase": "quiescing",
        "resume": True,
        "old": {"spki": "b" * 64, "chain": ["c" * 64]},
        "issued": None,
        "old_inode": [identity.st_dev, identity.st_ino],
        "stage_inode": None,
        "rollback_expected": False,
        "commit_possible": False,
    }
    for name, content in (
        (service.LOCK, b""),
        (service.JOURNAL, json.dumps(journal).encode("ascii")),
    ):
        path = root / name
        path.write_bytes(content)
        path.chmod(0o600)


def live_verified_normalization_state(root):
    canonical = root / service.CANONICAL
    canonical.write_bytes(b"public-test-old-keystore-placeholder")
    canonical.chmod(0o600)
    old_identity = canonical.stat()
    os.link(canonical, root / service.ROLLBACK)
    canonical.unlink()
    canonical.write_bytes(b"public-test-issued-keystore-placeholder")
    canonical.chmod(0o600)
    issued_identity = canonical.stat()
    journal = {
        "version": 1,
        "transaction": "a" * 32,
        "phase": "live_verified",
        "resume": True,
        "old": {"spki": "b" * 64, "chain": ["c" * 64]},
        "issued": {"spki": "b" * 64, "chain": ["d" * 64, "e" * 64]},
        "old_inode": [old_identity.st_dev, old_identity.st_ino],
        "stage_inode": [issued_identity.st_dev, issued_identity.st_ino],
        "rollback_expected": True,
        "commit_possible": True,
    }
    encoded = json.dumps(journal).encode("ascii")
    for name, content in (
        (service.LOCK, b""),
        (service.JOURNAL, encoded),
        (service.JOURNAL_NEW, encoded),
    ):
        path = root / name
        path.write_bytes(content)
        path.chmod(0o600)


def anchor_test_config(monkeypatch, tmp_path):
    original_open = os.open
    monkeypatch.setattr(
        service.os,
        "open",
        lambda path, flags, *args, **kwargs: original_open(
            str(tmp_path) if path == "/" else path, flags, *args, **kwargs
        ),
    )
    monkeypatch.setattr(service, "_local_identity", lambda: (os.getuid(), os.getgid()))


def clean_canonical_state(tmp_path, monkeypatch, mode=0o644):
    root = tmp_path / "config/data"
    root.mkdir(parents=True, mode=0o700)
    canonical = root / service.CANONICAL
    canonical.write_bytes(b"public-test-fresh-keystore-placeholder")
    canonical.chmod(mode)
    anchor_test_config(monkeypatch, tmp_path)
    monkeypatch.setattr(service.os, "fchown", lambda *args: None)
    return root, canonical


def test_clean_linuxserver_canonical_mode_is_normalized_without_changing_bytes(
    tmp_path, monkeypatch
):
    original_open = os.open
    root, canonical = clean_canonical_state(tmp_path, monkeypatch)
    contents = canonical.read_bytes()
    canonical_inode = canonical.stat().st_ino
    synced = []
    original_fsync = os.fsync

    def observe_fsync(fd):
        synced.append(os.fstat(fd))
        original_fsync(fd)

    monkeypatch.setattr(service.os, "fsync", observe_fsync)

    assert service.secure_after_linuxserver_init() == "executor_state_secured"
    assert stat.S_IMODE(canonical.stat().st_mode) == 0o600
    assert canonical.read_bytes() == contents
    assert any(item.st_ino == canonical_inode for item in synced)
    assert any(stat.S_ISDIR(item.st_mode) for item in synced)

    # Normal executor operation remains strict and accepts the normalized file.
    files = object.__new__(executor_files._Files)
    files.uid, files.gid = os.getuid(), os.getgid()
    files.root = str(root)
    files.fd = original_open(root, os.O_RDONLY | os.O_DIRECTORY)
    files.filesystem = "testfs"
    try:
        assert stat.S_IMODE(files.status(service.CANONICAL).st_mode) == 0o600
    finally:
        files.close()


def test_clean_secure_canonical_is_not_unnecessarily_mutated(tmp_path, monkeypatch):
    _, canonical = clean_canonical_state(tmp_path, monkeypatch, mode=0o600)
    canonical_inode = canonical.stat().st_ino
    chmod_inodes = []
    original_fchmod = os.fchmod

    def observe_fchmod(fd, mode):
        chmod_inodes.append(os.fstat(fd).st_ino)
        original_fchmod(fd, mode)

    monkeypatch.setattr(service.os, "fchmod", observe_fchmod)

    assert service.secure_after_linuxserver_init() == "executor_state_secured"
    assert stat.S_IMODE(canonical.stat().st_mode) == 0o600
    assert canonical_inode not in chmod_inodes


@pytest.mark.parametrize("mode", [0o666, 0o640])
def test_clean_canonical_with_unexpected_mode_is_rejected(tmp_path, monkeypatch, mode):
    _, canonical = clean_canonical_state(tmp_path, monkeypatch, mode=mode)
    with pytest.raises(UnifiOperationError):
        service.secure_after_linuxserver_init()
    assert stat.S_IMODE(canonical.stat().st_mode) == mode


def test_symlinked_clean_canonical_is_rejected(tmp_path, monkeypatch):
    root = tmp_path / "config/data"
    root.mkdir(parents=True, mode=0o700)
    target = root / "not-the-canonical-keystore"
    target.write_bytes(b"public-test-keystore-placeholder")
    target.chmod(0o600)
    (root / service.CANONICAL).symlink_to(target.name)
    anchor_test_config(monkeypatch, tmp_path)
    monkeypatch.setattr(service.os, "fchown", lambda *args: None)

    with pytest.raises(UnifiOperationError):
        service.secure_after_linuxserver_init()
    assert stat.S_IMODE(target.stat().st_mode) == 0o600


def test_hard_linked_clean_canonical_is_rejected(tmp_path, monkeypatch):
    root, canonical = clean_canonical_state(tmp_path, monkeypatch)
    os.link(canonical, root / "unexpected-hard-link")

    with pytest.raises(UnifiOperationError):
        service.secure_after_linuxserver_init()
    assert stat.S_IMODE(canonical.stat().st_mode) == 0o644


def test_non_regular_clean_canonical_is_rejected(tmp_path, monkeypatch):
    root = tmp_path / "config/data"
    root.mkdir(parents=True, mode=0o700)
    (root / service.CANONICAL).mkdir(mode=0o700)
    anchor_test_config(monkeypatch, tmp_path)
    monkeypatch.setattr(service.os, "fchown", lambda *args: None)

    with pytest.raises(UnifiOperationError):
        service.secure_after_linuxserver_init()


def test_oversized_clean_canonical_is_rejected(tmp_path, monkeypatch):
    _, canonical = clean_canonical_state(tmp_path, monkeypatch)
    with canonical.open("r+b") as stream:
        stream.truncate(service.MAX_STORE + 1)

    with pytest.raises(UnifiOperationError):
        service.secure_after_linuxserver_init()
    assert stat.S_IMODE(canonical.stat().st_mode) == 0o644


@pytest.mark.parametrize(
    "identity",
    [
        (os.getuid() + 1, os.getgid()),
        (os.getuid(), os.getgid() + 1),
    ],
)
def test_clean_canonical_with_wrong_local_identity_is_rejected(
    tmp_path, monkeypatch, identity
):
    root = tmp_path / "data"
    root.mkdir(mode=0o700)
    canonical = root / service.CANONICAL
    canonical.write_bytes(b"public-test-keystore-placeholder")
    canonical.chmod(0o644)
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(UnifiOperationError):
            service._normalize_clean_canonical(descriptor, *identity)
    finally:
        os.close(descriptor)
    assert stat.S_IMODE(canonical.stat().st_mode) == 0o644


def test_replaced_clean_canonical_during_chmod_fails_closed(tmp_path, monkeypatch):
    root, canonical = clean_canonical_state(tmp_path, monkeypatch)
    original_fchmod = os.fchmod
    canonical_inode = canonical.stat().st_ino

    def replace_during_canonical_chmod(fd, mode):
        if os.fstat(fd).st_ino == canonical_inode:
            replacement = root / "replacement"
            replacement.write_bytes(canonical.read_bytes())
            replacement.chmod(0o644)
            os.replace(replacement, canonical)
        original_fchmod(fd, mode)

    monkeypatch.setattr(service.os, "fchmod", replace_during_canonical_chmod)

    with pytest.raises(UnifiOperationError):
        service.secure_after_linuxserver_init()
    assert canonical.stat().st_ino != canonical_inode
    assert stat.S_IMODE(canonical.stat().st_mode) == 0o644


def test_pending_transaction_does_not_use_clean_install_mode_exception(
    tmp_path, monkeypatch
):
    root = tmp_path / "config/data"
    root.mkdir(parents=True, mode=0o700)
    pending_normalization_state(root)
    canonical = root / service.CANONICAL
    canonical.chmod(0o644)
    anchor_test_config(monkeypatch, tmp_path)
    ownership = []
    monkeypatch.setattr(
        service.os, "fchown", lambda fd, uid, gid: ownership.append((uid, gid))
    )

    with pytest.raises(UnifiOperationError):
        service.secure_after_linuxserver_init()
    assert ownership == []
    assert stat.S_IMODE(canonical.stat().st_mode) == 0o644


def mark_admin_entry_root_owned(monkeypatch, root_owned):
    original = service._admin_entry

    def mixed(root, name, descriptor, uid, gid):
        entry = original(root, name, descriptor, uid, gid)
        if name not in root_owned:
            return entry
        return SimpleNamespace(
            st_dev=entry.st_dev,
            st_ino=entry.st_ino,
            st_uid=0,
            st_gid=0,
        )

    monkeypatch.setattr(service, "_admin_entry", mixed)


def test_pre_recovery_normalization_accepts_valid_pending_transaction(
    tmp_path, monkeypatch
):
    root = tmp_path / "config/data"
    root.mkdir(parents=True, mode=0o700)
    pending_normalization_state(root)
    anchor_test_config(monkeypatch, tmp_path)
    restored = []
    monkeypatch.setattr(
        service.os, "fchown", lambda fd, uid, gid: restored.append((uid, gid))
    )
    assert service.secure_after_linuxserver_init() == "executor_state_secured"
    assert restored == [(0, 0), (0, 0)]


def test_interrupted_admin_file_restoration_converges_on_next_boot(
    tmp_path, monkeypatch
):
    root = tmp_path / "config/data"
    root.mkdir(parents=True, mode=0o700)
    pending_normalization_state(root)
    anchor_test_config(monkeypatch, tmp_path)
    calls = 0

    def interrupted(fd, uid, gid):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("simulated container stop between fixed files")

    monkeypatch.setattr(service.os, "fchown", interrupted)
    with pytest.raises(UnifiOperationError):
        service.secure_after_linuxserver_init()

    restored = []
    monkeypatch.setattr(
        service.os, "fchown", lambda fd, uid, gid: restored.append((uid, gid))
    )
    assert service.secure_after_linuxserver_init() == "executor_state_secured"
    assert restored == [(0, 0), (0, 0)]


def test_replaced_admin_file_during_restoration_fails_closed(tmp_path, monkeypatch):
    root = tmp_path / "config/data"
    root.mkdir(parents=True, mode=0o700)
    pending_normalization_state(root)
    anchor_test_config(monkeypatch, tmp_path)
    calls = 0

    def replace_journal(fd, uid, gid):
        nonlocal calls
        calls += 1
        if calls == 2:
            replacement = root / "replacement"
            replacement.write_bytes((root / service.JOURNAL).read_bytes())
            replacement.chmod(0o600)
            os.replace(replacement, root / service.JOURNAL)

    monkeypatch.setattr(service.os, "fchown", replace_journal)
    with pytest.raises(UnifiOperationError):
        service.secure_after_linuxserver_init()


def test_mismatched_pending_inode_is_rejected_before_any_ownership_change(
    tmp_path, monkeypatch
):
    root = tmp_path / "config/data"
    root.mkdir(parents=True, mode=0o700)
    pending_normalization_state(root)
    journal_path = root / service.JOURNAL
    journal = json.loads(journal_path.read_text(encoding="ascii"))
    journal["old_inode"][1] += 1
    journal_path.write_text(json.dumps(journal), encoding="ascii")
    journal_path.chmod(0o600)
    anchor_test_config(monkeypatch, tmp_path)
    ownership = []
    monkeypatch.setattr(
        service.os, "fchown", lambda fd, uid, gid: ownership.append((uid, gid))
    )
    with pytest.raises(UnifiOperationError):
        service.secure_after_linuxserver_init()
    assert ownership == []


def test_transaction_without_persistent_lock_is_rejected_without_mutation(
    tmp_path, monkeypatch
):
    root = tmp_path / "config/data"
    root.mkdir(parents=True, mode=0o700)
    pending_normalization_state(root)
    (root / service.LOCK).unlink()
    anchor_test_config(monkeypatch, tmp_path)
    ownership = []
    monkeypatch.setattr(
        service.os, "fchown", lambda fd, uid, gid: ownership.append((uid, gid))
    )

    with pytest.raises(UnifiOperationError):
        service.secure_after_linuxserver_init()

    assert ownership == []
    assert not (root / service.LOCK).exists()
    assert (root / service.JOURNAL).exists()


def test_phase_impossible_transaction_is_rejected_before_ownership_change(
    tmp_path, monkeypatch
):
    root = tmp_path / "config/data"
    root.mkdir(parents=True, mode=0o700)
    pending_normalization_state(root)
    stage = root / service.STAGE
    stage.write_bytes(b"public-test-staged-keystore-placeholder")
    stage.chmod(0o600)
    os.link(root / service.CANONICAL, root / service.ROLLBACK)
    journal_path = root / service.JOURNAL
    journal = json.loads(journal_path.read_text(encoding="ascii"))
    journal.update(
        {
            "phase": "quiescing",
            "issued": {"spki": "d" * 64, "chain": ["e" * 64]},
            "stage_inode": [stage.stat().st_dev, stage.stat().st_ino],
            "rollback_expected": True,
            "commit_possible": True,
        }
    )
    journal_path.write_text(json.dumps(journal), encoding="ascii")
    journal_path.chmod(0o600)
    anchor_test_config(monkeypatch, tmp_path)
    ownership = []
    monkeypatch.setattr(
        service.os, "fchown", lambda fd, uid, gid: ownership.append((uid, gid))
    )

    with pytest.raises(UnifiOperationError):
        service.secure_after_linuxserver_init()

    assert ownership == []


@pytest.mark.parametrize(
    ("root_owned", "rollback_present"),
    [
        pytest.param({service.LOCK}, True, id="root-lock"),
        pytest.param({service.JOURNAL_NEW}, False, id="root-temporary-no-rollback"),
    ],
)
def test_live_verified_temporary_journal_is_rejected_before_ownership_change(
    tmp_path, monkeypatch, root_owned, rollback_present
):
    root = tmp_path / "config/data"
    root.mkdir(parents=True, mode=0o700)
    live_verified_normalization_state(root)
    if not rollback_present:
        (root / service.ROLLBACK).unlink()
    anchor_test_config(monkeypatch, tmp_path)
    mark_admin_entry_root_owned(monkeypatch, root_owned)
    ownership = []
    monkeypatch.setattr(
        service.os, "fchown", lambda fd, uid, gid: ownership.append((uid, gid))
    )

    with pytest.raises(UnifiOperationError):
        service.secure_after_linuxserver_init()

    assert ownership == []
    assert (root / service.JOURNAL).exists()
    assert (root / service.JOURNAL_NEW).exists()


@pytest.mark.parametrize("phase", ["quiescing", "recovered_old"])
def test_reachable_temporary_journal_is_repaired_without_parsing_contents(
    tmp_path, monkeypatch, phase
):
    root = tmp_path / "config/data"
    root.mkdir(parents=True, mode=0o700)
    pending_normalization_state(root)
    journal_path = root / service.JOURNAL
    journal = json.loads(journal_path.read_text(encoding="ascii"))
    journal["phase"] = phase
    journal_path.write_text(json.dumps(journal), encoding="ascii")
    journal_path.chmod(0o600)
    temporary = root / service.JOURNAL_NEW
    temporary.write_bytes(b'{"version":')
    temporary.chmod(0o600)
    anchor_test_config(monkeypatch, tmp_path)
    ownership = []
    monkeypatch.setattr(
        service.os, "fchown", lambda fd, uid, gid: ownership.append((uid, gid))
    )

    assert service.secure_after_linuxserver_init() == "executor_state_secured"
    assert ownership == [(0, 0), (0, 0), (0, 0)]


def test_temporary_journal_without_primary_is_rejected_before_ownership_change(
    tmp_path, monkeypatch
):
    root = tmp_path / "config/data"
    root.mkdir(parents=True, mode=0o700)
    for name, content in ((service.LOCK, b""), (service.JOURNAL_NEW, b"partial")):
        path = root / name
        path.write_bytes(content)
        path.chmod(0o600)
    anchor_test_config(monkeypatch, tmp_path)
    ownership = []
    monkeypatch.setattr(
        service.os, "fchown", lambda fd, uid, gid: ownership.append((uid, gid))
    )

    with pytest.raises(UnifiOperationError):
        service.secure_after_linuxserver_init()

    assert ownership == []


def test_post_init_hook_rejects_symlinked_admin_state(tmp_path, monkeypatch):
    root = tmp_path / "config/data"
    root.mkdir(parents=True, mode=0o700)
    lock = root / service.LOCK
    lock.write_bytes(b"")
    lock.chmod(0o600)
    (root / service.JOURNAL).symlink_to(lock)
    original_open = os.open
    monkeypatch.setattr(
        service.os,
        "open",
        lambda path, flags, *args, **kwargs: original_open(
            str(tmp_path) if path == "/" else path, flags, *args, **kwargs
        ),
    )
    monkeypatch.setattr(service, "_local_identity", lambda: (os.getuid(), os.getgid()))
    monkeypatch.setattr(service.os, "fchown", lambda *args: None)
    with pytest.raises(UnifiOperationError):
        service.secure_after_linuxserver_init()


def test_socket_directory_permission_prerequisites_fail_closed(monkeypatch):
    safe = SimpleNamespace(st_mode=stat_mode(0o750), st_uid=0, st_gid=991)
    monkeypatch.setattr(service.os, "stat", lambda *args, **kwargs: safe)
    assert service._validate_socket_directory() is safe
    for mode, owner in ((0o770, 0), (0o750, 1000), (0o755, 0)):
        unsafe = SimpleNamespace(st_mode=stat_mode(mode), st_uid=owner, st_gid=991)
        monkeypatch.setattr(
            service.os, "stat", lambda *args, value=unsafe, **kwargs: value
        )
        with pytest.raises(UnifiOperationError):
            service._validate_socket_directory()


def test_fifo_socket_lock_is_rejected_without_blocking(tmp_path):
    os.mkfifo(tmp_path / service.SOCKET_LOCK, 0o600)
    directory = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(UnifiOperationError):
            service._open_socket_lock(directory)
    finally:
        os.close(directory)


@pytest.mark.parametrize(
    ("stage", "group"),
    [("after-bind", 0), ("after-chown", 991), ("after-chmod", 991)],
)
def test_recognizable_interrupted_socket_publication_is_restart_safe(
    monkeypatch, stage, group
):
    directory = SimpleNamespace(st_dev=7, st_gid=991)
    stale = SimpleNamespace(
        st_mode=stat.S_IFSOCK | 0o660,
        st_uid=0,
        st_gid=group,
        st_nlink=1,
        st_dev=7,
    )
    exists = True
    removed = []

    def socket_status(*args, **kwargs):
        if exists:
            return stale
        raise FileNotFoundError

    def unlink(name, **kwargs):
        nonlocal exists
        assert name == "executor.sock"
        exists = False
        removed.append(stage)

    monkeypatch.setattr(service.os, "stat", socket_status)
    monkeypatch.setattr(service.os, "unlink", unlink)
    service._remove_stale_socket(3, directory)
    service._remove_stale_socket(3, directory)
    assert removed == [stage]


@pytest.mark.parametrize(
    "unsafe",
    [
        SimpleNamespace(
            st_mode=stat.S_IFREG | 0o660,
            st_uid=0,
            st_gid=991,
            st_nlink=1,
            st_dev=7,
        ),
        SimpleNamespace(
            st_mode=stat.S_IFLNK | 0o660,
            st_uid=0,
            st_gid=991,
            st_nlink=1,
            st_dev=7,
        ),
        SimpleNamespace(
            st_mode=stat.S_IFSOCK | 0o660,
            st_uid=1000,
            st_gid=991,
            st_nlink=1,
            st_dev=7,
        ),
        SimpleNamespace(
            st_mode=stat.S_IFSOCK | 0o666,
            st_uid=0,
            st_gid=991,
            st_nlink=1,
            st_dev=7,
        ),
        SimpleNamespace(
            st_mode=stat.S_IFSOCK | 0o660,
            st_uid=0,
            st_gid=992,
            st_nlink=1,
            st_dev=7,
        ),
    ],
)
def test_unsafe_socket_replacement_is_rejected_without_unlink(monkeypatch, unsafe):
    removed = []
    monkeypatch.setattr(service.os, "stat", lambda *args, **kwargs: unsafe)
    monkeypatch.setattr(service.os, "unlink", lambda *args, **kwargs: removed.append(1))
    with pytest.raises(UnifiOperationError):
        service._remove_stale_socket(3, SimpleNamespace(st_dev=7, st_gid=991))
    assert removed == []


def stat_mode(mode):
    return 0o040000 | mode


def test_client_surface_has_no_path_command_alias_or_service_parameters():
    boundary = service.SocketUnifiExecutionBoundary()
    assert set(vars(boundary)) == {"_exclusive", "_installed"}
    with pytest.raises(TypeError):
        service.SocketUnifiExecutionBoundary(socket_path="/tmp/other")
