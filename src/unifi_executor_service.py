"""Fixed Unix-socket boundary for the key-owner-local UniFi executor.

The wire protocol is deliberately not extensible: version 1 has five semantic
operations and every request/response shape is closed.  It never accepts a
command, executable, argv, alias, service name, pathname, or secret.
"""

import base64
import binascii
import fcntl
import json
import os
import socket
import stat
import struct
import sys
import time
from contextlib import contextmanager

from unifi_client import (
    MAX_CERTIFICATE_DER_BYTES,
    MAX_KEYTOOL_OUTPUT_CHARS,
    CertificateImportRequest,
    CertificatePolicy,
    PublicKeystoreState,
    UnifiClient,
    UnifiOperationError,
    build_unifi_csr_command,
    inspect_public_keystore_state,
    prepare_certificate_import,
)
from unifi_executor import ProductionUnifiExecutor, _local_identity, _validate_journal
from unifi_executor_client import SocketUnifiExecutionBoundary
from unifi_executor_files import (
    CANONICAL,
    JOURNAL,
    JOURNAL_NEW,
    LOCK,
    MAX_JOURNAL,
    MAX_STORE,
    ROLLBACK,
    STAGE,
)

__all__ = ["SocketUnifiExecutionBoundary", "main"]

PROTOCOL_VERSION = 1
SOCKET_DIRECTORY = "/run/unifi-cert-renewer"
SOCKET_PATH = f"{SOCKET_DIRECTORY}/executor.sock"
SOCKET_LOCK = ".executor-socket.lock"
MAX_MESSAGE_BYTES = 8 * 1024 * 1024
SOCKET_TIMEOUT_SECONDS = 300.0
REQUEST_READ_TIMEOUT_SECONDS = 10.0
_OPERATIONS = frozenset({"inspect", "generate_csr", "install", "recover", "finalize"})
_RECOVERY_RESULTS = frozenset(
    {
        "no_active_transaction",
        "recovered_old",
        "service_resumed_pending_live_verification",
        "renewal_finalized",
    }
)
_JOURNAL_NEW_PHASES = frozenset(
    {
        "quiescing",
        "quiesced",
        "staging",
        "staged_validated",
        "rollback_durable",
        "commit_possible",
        "committed",
        "canonical_verified",
        "service_resumed_pending_live_verification",
        "recovery_required",
        "recovered_old",
    }
)
_monotonic = time.monotonic


def _object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError
        value[key] = item
    return value


def _exact_dict(value, fields):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise ValueError
    return value


def _binary(value, *, maximum=MAX_KEYTOOL_OUTPUT_CHARS):
    if not isinstance(value, str) or len(value) > ((maximum + 2) // 3) * 4:
        raise ValueError
    try:
        result = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        raise ValueError from None
    if len(result) > maximum:
        raise ValueError
    return result


def _encode_binary(value):
    if not isinstance(value, bytes):
        raise ValueError
    return base64.b64encode(value).decode("ascii")


def _encode_state(state):
    inspect_public_keystore_state(state)
    return {
        "keytool_output": state.keytool_output,
        "certificate_chain_der": [
            _encode_binary(item) for item in state.certificate_chain_der
        ],
    }


def _decode_state(value):
    value = _exact_dict(value, {"keytool_output", "certificate_chain_der"})
    output = value["keytool_output"]
    chain = value["certificate_chain_der"]
    if (
        not isinstance(output, str)
        or len(output) > MAX_KEYTOOL_OUTPUT_CHARS
        or not isinstance(chain, list)
        or not 1 <= len(chain) <= 10
    ):
        raise ValueError
    state = PublicKeystoreState(
        output,
        tuple(_binary(item, maximum=MAX_CERTIFICATE_DER_BYTES) for item in chain),
    )
    inspect_public_keystore_state(state)
    return state


def _encode_policy(policy):
    return {
        "expected_spki_sha256": policy.expected_spki_sha256,
        "subject": policy.subject,
        "dns_sans": list(policy.dns_sans),
        "ip_sans": list(policy.ip_sans),
    }


def _decode_policy(value):
    value = _exact_dict(
        value, {"expected_spki_sha256", "subject", "dns_sans", "ip_sans"}
    )
    if not isinstance(value["dns_sans"], list) or not isinstance(
        value["ip_sans"], list
    ):
        raise ValueError
    policy = CertificatePolicy(
        expected_spki_sha256=value["expected_spki_sha256"],
        subject=value["subject"],
        dns_sans=tuple(value["dns_sans"]),
        ip_sans=tuple(value["ip_sans"]),
    )
    # The shared validator fixes and validates alias, paths and command semantics.
    build_unifi_csr_command(policy)
    return policy


def _encode_import_request(request):
    return {
        "before": _encode_state(request.before),
        "policy": _encode_policy(request.policy),
        "csr_pem": _encode_binary(request.csr_pem),
        "issued_certificate": _encode_binary(request.issued_certificate),
        "trusted_ca_data": _encode_binary(request.trusted_ca_data),
        "lifetime_days": request.lifetime_days,
    }


def _decode_import_request(value):
    value = _exact_dict(
        value,
        {
            "before",
            "policy",
            "csr_pem",
            "issued_certificate",
            "trusted_ca_data",
            "lifetime_days",
        },
    )
    request = CertificateImportRequest(
        before=_decode_state(value["before"]),
        policy=_decode_policy(value["policy"]),
        csr_pem=_binary(value["csr_pem"]),
        issued_certificate=_binary(
            value["issued_certificate"], maximum=MAX_CERTIFICATE_DER_BYTES
        ),
        trusted_ca_data=_binary(value["trusted_ca_data"]),
        lifetime_days=value["lifetime_days"],
    )
    prepare_certificate_import(request)
    return request


def _read_message(connection, *, deadline=None):
    if deadline is None:
        deadline = _monotonic() + SOCKET_TIMEOUT_SECONDS
    header = _read_exact(connection, 4, deadline=deadline)
    length = struct.unpack("!I", header)[0]
    if not 1 <= length <= MAX_MESSAGE_BYTES:
        raise ValueError
    data = _read_exact(connection, length, deadline=deadline)
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=_object)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError from None


def _read_exact(connection, length, *, deadline):
    data = bytearray()
    while len(data) < length:
        remaining = deadline - _monotonic()
        if remaining <= 0:
            raise TimeoutError
        connection.settimeout(remaining)
        chunk = connection.recv(length - len(data))
        if not chunk:
            raise ValueError
        data.extend(chunk)
    return bytes(data)


def _write_message(connection, value):
    data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
    if len(data) > MAX_MESSAGE_BYTES:
        raise ValueError
    connection.sendall(struct.pack("!I", len(data)) + data)


def _request(operation, arguments):
    if operation not in _OPERATIONS or not isinstance(arguments, dict):
        raise ValueError
    return {"version": PROTOCOL_VERSION, "operation": operation, "arguments": arguments}


def _decode_envelope(value):
    value = _exact_dict(value, {"version", "operation", "arguments"})
    if (
        type(value["version"]) is not int
        or value["version"] != PROTOCOL_VERSION
        or not isinstance(value["operation"], str)
        or value["operation"] not in _OPERATIONS
    ):
        raise ValueError
    if not isinstance(value["arguments"], dict):
        raise ValueError
    return value["operation"], value["arguments"]


def _decode_response(response):
    if not isinstance(response, dict):
        raise ValueError
    response = _exact_dict(
        response,
        {"version", "ok", "result"}
        if response.get("ok") is True
        else {"version", "ok", "error"},
    )
    if (
        type(response["version"]) is not int
        or response["version"] != PROTOCOL_VERSION
        or response["ok"] is not True
    ):
        raise ValueError
    return response["result"]


def _inspection_state(inspection, chain):
    output = (
        f"Keystore type: {inspection.keystore.keystore_type}\n"
        f"Keystore provider: {inspection.keystore.provider}\n"
        f"Alias name: {inspection.alias.alias_name}\n"
        f"Entry type: {inspection.alias.entry_type}\n"
        f"Certificate chain length: {inspection.alias.certificate_chain_length}\n"
    )
    state = PublicKeystoreState(output, chain)
    inspect_public_keystore_state(state)
    return state


class _ProtocolHandler:
    """Server-side fixed operation dispatch; factory injection is test-only."""

    def __init__(self, executor_factory=ProductionUnifiExecutor):
        self._executor_factory = executor_factory

    def dispatch(self, request):
        operation, arguments = _decode_envelope(request)
        executor = self._executor_factory()
        if operation in {"inspect", "recover"}:
            _exact_dict(arguments, set())
        if operation == "inspect":
            return {"state": _encode_state(executor.inspect_public_state())}
        if operation == "generate_csr":
            _exact_dict(arguments, {"policy"})
            return {
                "csr_pem": _encode_binary(
                    executor.generate_csr(_decode_policy(arguments["policy"]))
                )
            }
        if operation == "install":
            _exact_dict(arguments, {"request"})
            certificate_request = _decode_import_request(arguments["request"])
            inspection = UnifiClient(executor).install_certificate(certificate_request)
            plan = prepare_certificate_import(certificate_request)
            after = _inspection_state(inspection, plan.certificate_chain_der)
            return {"state": _encode_state(after)}
        if operation == "recover":
            outcome = executor.recover()
            if outcome not in _RECOVERY_RESULTS:
                raise ValueError
            return {"outcome": outcome}
        _exact_dict(arguments, {"expected_leaf_der"})
        outcome = executor.finalize_live_verification(
            _binary(arguments["expected_leaf_der"], maximum=MAX_CERTIFICATE_DER_BYTES)
        )
        if outcome != "renewal_finalized":
            raise ValueError
        return {"outcome": outcome}

    def handle(self, connection):
        try:
            request_deadline = _monotonic() + REQUEST_READ_TIMEOUT_SECONDS
            request = _read_message(connection, deadline=request_deadline)
            connection.settimeout(SOCKET_TIMEOUT_SECONDS)
            result = self.dispatch(request)
            response = {"version": PROTOCOL_VERSION, "ok": True, "result": result}
        except Exception:
            # Never reflect request data, child diagnostics, paths, or credentials.
            response = {
                "version": PROTOCOL_VERSION,
                "ok": False,
                "error": "executor_operation_failed",
            }
        try:
            _write_message(connection, response)
        except OSError:
            # The semantic operation has already completed or failed. A client
            # disconnect cannot cancel it and is not a server-wide failure.
            return False
        return True


def _validate_socket_directory():
    info = os.stat(SOCKET_DIRECTORY, follow_symlinks=False)
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != 0
        or stat.S_IMODE(info.st_mode) != 0o750
    ):
        raise UnifiOperationError("unsafe executor socket directory")
    return info


def _open_socket_lock(directory_fd):
    flags = os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    try:
        expected = os.stat(SOCKET_LOCK, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        lock = os.open(
            SOCKET_LOCK, flags | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=directory_fd
        )
        try:
            os.fchown(lock, 0, 0)
            os.fchmod(lock, 0o600)
            expected = os.stat(SOCKET_LOCK, dir_fd=directory_fd, follow_symlinks=False)
        except BaseException:
            os.close(lock)
            raise
    else:
        lock = os.open(SOCKET_LOCK, flags, dir_fd=directory_fd)
    actual = os.fstat(lock)
    if (
        not stat.S_ISREG(expected.st_mode)
        or stat.S_IMODE(expected.st_mode) != 0o600
        or (expected.st_uid, expected.st_gid, expected.st_nlink) != (0, 0, 1)
        or (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino)
    ):
        os.close(lock)
        raise UnifiOperationError("unsafe executor socket lock")
    return lock


def _remove_stale_socket(directory_fd, directory):
    try:
        existing = os.stat("executor.sock", dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    # bind() publishes a root-owned 0660 socket atomically under the controlled
    # umask below. A crash may leave its group as root before chown completes.
    # The locked 0750 directory is not writable by the invoking group, so no
    # unprivileged caller can manufacture either accepted state.
    if (
        not stat.S_ISSOCK(existing.st_mode)
        or stat.S_IMODE(existing.st_mode) != 0o660
        or existing.st_uid != 0
        or existing.st_gid not in {0, directory.st_gid}
        or existing.st_nlink != 1
        or existing.st_dev != directory.st_dev
    ):
        raise UnifiOperationError("unsafe existing executor socket")
    os.unlink("executor.sock", dir_fd=directory_fd)


@contextmanager
def _listener():
    directory = _validate_socket_directory()
    directory_fd = os.open(
        SOCKET_DIRECTORY, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    )
    lock = listener = None
    socket_identity = None
    try:
        if (os.fstat(directory_fd).st_dev, os.fstat(directory_fd).st_ino) != (
            directory.st_dev,
            directory.st_ino,
        ):
            raise UnifiOperationError("executor socket directory changed")
        lock = _open_socket_lock(directory_fd)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        _remove_stale_socket(directory_fd, directory)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        previous_umask = os.umask(0o117)
        try:
            listener.bind(SOCKET_PATH)
        finally:
            os.umask(previous_umask)
        created = os.stat("executor.sock", dir_fd=directory_fd, follow_symlinks=False)
        if (
            not stat.S_ISSOCK(created.st_mode)
            or stat.S_IMODE(created.st_mode) != 0o660
            or created.st_uid != 0
            or created.st_gid not in {0, directory.st_gid}
            or created.st_nlink != 1
            or created.st_dev != directory.st_dev
        ):
            raise UnifiOperationError("unsafe newly bound executor socket")
        socket_identity = (created.st_dev, created.st_ino)
        os.chown(SOCKET_PATH, 0, directory.st_gid, follow_symlinks=False)
        os.chmod(SOCKET_PATH, 0o660, follow_symlinks=False)
        created = os.stat("executor.sock", dir_fd=directory_fd, follow_symlinks=False)
        if (
            (created.st_dev, created.st_ino) != socket_identity
            or not stat.S_ISSOCK(created.st_mode)
            or stat.S_IMODE(created.st_mode) != 0o660
            or (created.st_uid, created.st_gid, created.st_nlink)
            != (0, directory.st_gid, 1)
        ):
            raise UnifiOperationError("executor socket changed during setup")
        listener.listen(4)
        yield listener
    except (OSError, ValueError):
        raise UnifiOperationError("executor socket setup failed") from None
    finally:
        if listener is not None:
            listener.close()
        if socket_identity is not None:
            try:
                existing = os.stat(
                    "executor.sock", dir_fd=directory_fd, follow_symlinks=False
                )
                if (existing.st_dev, existing.st_ino) == socket_identity:
                    os.unlink("executor.sock", dir_fd=directory_fd)
            except FileNotFoundError:
                pass
        if lock is not None:
            os.close(lock)
        os.close(directory_fd)


def _serve_client(handler, connection):
    with connection:
        handler.handle(connection)


def serve_forever():
    handler = _ProtocolHandler()
    with _listener() as listener:
        while True:
            connection, _ = listener.accept()
            _serve_client(handler, connection)


def _startup_data_directory_absent():
    """Allow LinuxServer to initialize a genuinely new empty /config volume."""
    config = os.open(
        "/config", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    )
    try:
        info = os.fstat(config)
        if info.st_uid not in {0, 1000} or info.st_mode & 0o022:
            raise UnifiOperationError("unsafe UniFi configuration directory")
        try:
            os.stat("data", dir_fd=config, follow_symlinks=False)
        except FileNotFoundError:
            return True
        return False
    finally:
        os.close(config)


def recover_startup():
    if _startup_data_directory_absent():
        return "no_active_transaction"
    # LinuxServer may have been interrupted after recursively changing appdata
    # ownership on the previous boot. Normalize only validated executor admin
    # files before the strict executor attempts to open them.
    secure_after_linuxserver_init()
    # The recovery decision and cleanup complete before the dependent s6 longrun
    # becomes eligible.  Do not start Java from inside this oneshot.
    outcome = ProductionUnifiExecutor().recover(startup=True)
    if outcome not in _RECOVERY_RESULTS:
        raise UnifiOperationError("unexpected startup recovery result")
    return outcome


def _admin_entry(root, name, descriptor, uid, gid):
    before = os.stat(name, dir_fd=root, follow_symlinks=False)
    opened = os.fstat(descriptor)
    maximum = 0 if name == LOCK else MAX_JOURNAL
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_IMODE(before.st_mode) != 0o600
        or (before.st_uid, before.st_gid) not in {(0, 0), (uid, gid)}
        or before.st_dev != os.fstat(root).st_dev
        or not 0 <= before.st_size <= maximum
        or before.st_nlink != 1
        or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
    ):
        raise UnifiOperationError("unsafe executor administration state")
    return before


def _transaction_entry(root, name, uid, gid):
    try:
        value = os.stat(name, dir_fd=root, follow_symlinks=False)
    except FileNotFoundError:
        return None
    links = {1, 2} if name in {CANONICAL, ROLLBACK} else {1}
    if (
        not stat.S_ISREG(value.st_mode)
        or stat.S_IMODE(value.st_mode) != 0o600
        or (value.st_uid, value.st_gid) != (uid, gid)
        or value.st_dev != os.fstat(root).st_dev
        or not 0 <= value.st_size <= MAX_STORE
        or value.st_nlink not in links
    ):
        raise UnifiOperationError("unsafe transaction state during normalization")
    return value


def _path_exists(root, name):
    try:
        os.stat(name, dir_fd=root, follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False


def _normalize_clean_canonical(root, uid, gid):
    """Narrowly normalize LinuxServer's fresh canonical keystore mode."""
    try:
        before = os.stat(CANONICAL, dir_fd=root, follow_symlinks=False)
    except FileNotFoundError:
        return

    descriptor = os.open(
        CANONICAL,
        os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
        dir_fd=root,
    )
    try:
        opened = os.fstat(descriptor)
        root_device = os.fstat(root).st_dev
        mode = stat.S_IMODE(before.st_mode)
        if (
            not stat.S_ISREG(before.st_mode)
            or not stat.S_ISREG(opened.st_mode)
            or mode not in {0o600, 0o644}
            or stat.S_IMODE(opened.st_mode) != mode
            or (before.st_uid, before.st_gid) != (uid, gid)
            or (opened.st_uid, opened.st_gid) != (uid, gid)
            or before.st_dev != root_device
            or opened.st_dev != root_device
            or not 0 <= before.st_size <= MAX_STORE
            or opened.st_size != before.st_size
            or before.st_nlink != 1
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
        ):
            raise UnifiOperationError("unsafe fresh canonical keystore")

        if mode == 0o600:
            return

        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
        current = os.stat(CANONICAL, dir_fd=root, follow_symlinks=False)
        normalized = os.fstat(descriptor)
        if (
            not stat.S_ISREG(current.st_mode)
            or not stat.S_ISREG(normalized.st_mode)
            or stat.S_IMODE(current.st_mode) != 0o600
            or stat.S_IMODE(normalized.st_mode) != 0o600
            or (current.st_uid, current.st_gid) != (uid, gid)
            or (normalized.st_uid, normalized.st_gid) != (uid, gid)
            or current.st_dev != root_device
            or normalized.st_dev != root_device
            or not 0 <= current.st_size <= MAX_STORE
            or normalized.st_size != current.st_size
            or current.st_nlink != 1
            or normalized.st_nlink != 1
            or (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino)
            or (normalized.st_dev, normalized.st_ino) != (before.st_dev, before.st_ino)
        ):
            raise UnifiOperationError("canonical keystore changed during normalization")
    finally:
        os.close(descriptor)


def _validate_normalization_transaction(
    root, journal, uid, gid, *, temporary_journal_present
):
    journal = _validate_journal(journal)
    progress = (
        journal["issued"] is not None,
        journal["stage_inode"] is not None,
        journal["rollback_expected"],
        journal["commit_possible"],
    )
    progress_initial = (False, False, False, False)
    progress_staging = (True, False, False, False)
    progress_staged = (True, True, False, False)
    progress_rollback = (True, True, True, False)
    progress_committable = (True, True, True, True)
    allowed_progress = {
        "quiescing": {progress_initial},
        "quiesced": {progress_initial},
        "staging": {progress_staging, progress_staged},
        "staged_validated": {progress_staged},
        "rollback_durable": {progress_rollback},
        "commit_possible": {progress_committable},
        "committed": {progress_committable},
        "canonical_verified": {progress_committable},
        "service_resumed_pending_live_verification": {progress_committable},
        "live_verified": {progress_committable},
        "recovery_required": {
            progress_initial,
            progress_staging,
            progress_staged,
            progress_rollback,
            progress_committable,
        },
        "recovered_old": {
            progress_initial,
            progress_staging,
            progress_staged,
            progress_rollback,
            progress_committable,
        },
    }
    if progress not in allowed_progress[journal["phase"]]:
        raise UnifiOperationError("unreachable transaction phase during normalization")

    canonical = _transaction_entry(root, CANONICAL, uid, gid)
    if canonical is None:
        raise UnifiOperationError("canonical keystore missing during normalization")
    canonical_identity = (canonical.st_dev, canonical.st_ino)
    old_identity = tuple(journal["old_inode"])
    stage_identity = (
        tuple(journal["stage_inode"]) if journal["stage_inode"] is not None else None
    )
    if journal["phase"] in {
        "committed",
        "canonical_verified",
        "service_resumed_pending_live_verification",
        "live_verified",
    }:
        allowed_canonical = {stage_identity}
    elif journal["phase"] == "commit_possible" or (
        journal["phase"] == "recovery_required" and progress == progress_committable
    ):
        allowed_canonical = {old_identity, stage_identity}
    else:
        allowed_canonical = {old_identity}
    if canonical_identity not in allowed_canonical:
        raise UnifiOperationError("canonical identity changed during normalization")

    rollback_entry = _transaction_entry(root, ROLLBACK, uid, gid)
    if (
        rollback_entry is not None
        and (
            rollback_entry.st_dev,
            rollback_entry.st_ino,
        )
        != old_identity
    ):
        raise UnifiOperationError("rollback identity changed during normalization")
    stage_entry = _transaction_entry(root, STAGE, uid, gid)
    if (
        stage_entry is not None
        and stage_identity is not None
        and (stage_entry.st_dev, stage_entry.st_ino) != stage_identity
    ):
        raise UnifiOperationError("stage identity changed during normalization")

    if journal["phase"] not in {"recovered_old", "recovery_required"}:
        if progress == progress_initial and (
            stage_entry is not None or rollback_entry is not None
        ):
            raise UnifiOperationError("unexpected early transaction artifacts")
        if progress == progress_staging and rollback_entry is not None:
            raise UnifiOperationError("unexpected staging rollback")
    if (
        journal["phase"]
        in {
            "committed",
            "canonical_verified",
            "service_resumed_pending_live_verification",
            "live_verified",
        }
        and stage_entry is not None
    ):
        raise UnifiOperationError("unexpected committed stage")
    # The copy is created before its inode is journalled, so either stage
    # presence is reachable while only the issued identity is durable.
    if journal["phase"] != "recovered_old" and progress != progress_staging:
        stage_required = progress in {progress_staged, progress_rollback} or (
            progress == progress_committable and canonical_identity == old_identity
        )
        if stage_required != (stage_entry is not None):
            raise UnifiOperationError("inconsistent transaction stage")
    rollback_required = journal["phase"] in {
        "rollback_durable",
        "commit_possible",
        "committed",
        "canonical_verified",
        "service_resumed_pending_live_verification",
    } or (
        journal["phase"] == "recovery_required"
        and progress in {progress_rollback, progress_committable}
    )
    if rollback_required and rollback_entry is None:
        raise UnifiOperationError("required transaction rollback missing")
    if (
        rollback_entry is not None
        and progress in {progress_initial, progress_staging}
        and journal["phase"] not in {"recovered_old"}
    ):
        raise UnifiOperationError("unexpected transaction rollback")
    # Listed phases can enter or retry a later journal write. live_verified can
    # only establish its barrier and clean up, and the atomic rename that
    # published it consumed its temporary source name. Future phases fail closed
    # until their write transitions are reviewed and explicitly added.
    if temporary_journal_present and journal["phase"] not in _JOURNAL_NEW_PHASES:
        raise UnifiOperationError("unexpected phase temporary journal")


def secure_after_linuxserver_init():
    """Normalize only proved executor admin files after an interrupted chown."""
    uid, gid = _local_identity()
    root = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    descriptors = {}
    admin_entries = {}
    try:
        for part in ("config", "data"):
            opened = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=root,
            )
            os.close(root)
            root = opened
            info = os.fstat(root)
            if info.st_uid not in {0, uid} or info.st_mode & 0o022:
                raise UnifiOperationError(
                    "unsafe appdata directory after initialization"
                )

        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
        if not _path_exists(root, LOCK):
            if any(
                _path_exists(root, name)
                for name in (JOURNAL, JOURNAL_NEW, STAGE, ROLLBACK)
            ):
                raise UnifiOperationError("transaction state exists without lock")
            descriptor = os.open(
                LOCK, flags | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=root
            )
            descriptors[LOCK] = descriptor
            os.fchmod(descriptor, 0o600)
        else:
            descriptor = os.open(LOCK, flags, dir_fd=root)
            descriptors[LOCK] = descriptor
        admin_entries[LOCK] = _admin_entry(root, LOCK, descriptor, uid, gid)
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)

        transaction_evidence = any(
            _path_exists(root, name) for name in (JOURNAL, JOURNAL_NEW, STAGE, ROLLBACK)
        )

        for name in (JOURNAL, JOURNAL_NEW):
            try:
                descriptor = os.open(name, flags, dir_fd=root)
            except FileNotFoundError:
                continue
            descriptors[name] = descriptor
            admin_entries[name] = _admin_entry(root, name, descriptor, uid, gid)

        repair = [
            name
            for name, entry in admin_entries.items()
            if (entry.st_uid, entry.st_gid) == (uid, gid)
        ]
        if repair and JOURNAL_NEW in descriptors and JOURNAL not in descriptors:
            raise UnifiOperationError("temporary journal has no durable authority")
        if repair and JOURNAL in descriptors:
            data = os.read(descriptors[JOURNAL], MAX_JOURNAL + 1)
            if len(data) > MAX_JOURNAL:
                raise UnifiOperationError("recovery journal exceeds limit")
            journal = json.loads(data.decode("ascii"), object_pairs_hook=_object)
            _validate_normalization_transaction(
                root,
                journal,
                uid,
                gid,
                temporary_journal_present=JOURNAL_NEW in descriptors,
            )

        # LinuxServer creates a new canonical keystore as abc:abc 0644.  That
        # compatibility exception is safe only when the lock proves there is no
        # active or recoverable transaction whose inode relationships govern the
        # canonical file.  Transaction paths remain strict 0600-only.
        if not transaction_evidence:
            _normalize_clean_canonical(root, uid, gid)

        # All names and transaction identity were proved before the first chown.
        # A crash between these fixed operations is restart-safe because mixed
        # root/abc ownership is accepted and revalidated on the next boot.
        identities = {
            name: (entry.st_dev, entry.st_ino) for name, entry in admin_entries.items()
        }
        for name in repair:
            descriptor = descriptors[name]
            before = os.fstat(descriptor)
            if (before.st_dev, before.st_ino) != identities[name]:
                raise UnifiOperationError(
                    "executor state changed before ownership normalization"
                )
            os.fchown(descriptor, 0, 0)
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
        for name, identity in identities.items():
            current = os.stat(name, dir_fd=root, follow_symlinks=False)
            if (
                (current.st_dev, current.st_ino) != identity
                or not stat.S_ISREG(current.st_mode)
                or stat.S_IMODE(current.st_mode) != 0o600
                or current.st_nlink != 1
            ):
                raise UnifiOperationError(
                    "executor state changed during ownership normalization"
                )
        os.fsync(root)
    except Exception:
        raise UnifiOperationError("executor state normalization failed") from None
    finally:
        for descriptor in descriptors.values():
            os.close(descriptor)
        os.close(root)
    return "executor_state_secured"


def main(argv=None):
    arguments = sys.argv[1:] if argv is None else argv
    try:
        if arguments == ["serve"]:
            serve_forever()
        elif arguments == ["recover-startup"]:
            outcome = recover_startup()
            print(f"unifi-cert-renewer startup recovery: {outcome}")
        elif arguments == ["secure-after-init"]:
            outcome = recover_startup()
            print(
                "unifi-cert-renewer executor state secured after LinuxServer init; "
                f"recovery recheck: {outcome}"
            )
        else:
            raise UnifiOperationError("unsupported executor entrypoint")
    except Exception:
        if arguments == ["recover-startup"]:
            message = (
                "unifi-cert-renewer startup recovery failed closed; "
                "operator review required"
            )
        elif arguments == ["secure-after-init"]:
            message = (
                "unifi-cert-renewer post-init state check failed closed; "
                "operator review required"
            )
        else:
            message = "unifi-cert-renewer executor failed closed"
        print(message, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
