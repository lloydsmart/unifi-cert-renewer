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
from unifi_executor import ProductionUnifiExecutor, _local_identity
from unifi_executor_files import JOURNAL, JOURNAL_NEW, LOCK, MAX_JOURNAL

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


def _read_message(connection):
    header = _read_exact(connection, 4)
    length = struct.unpack("!I", header)[0]
    if not 1 <= length <= MAX_MESSAGE_BYTES:
        raise ValueError
    data = _read_exact(connection, length)
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=_object)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError from None


def _read_exact(connection, length):
    data = bytearray()
    while len(data) < length:
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
        connection.settimeout(REQUEST_READ_TIMEOUT_SECONDS)
        try:
            request = _read_message(connection)
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
        _write_message(connection, response)


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
        try:
            existing = os.stat(
                "executor.sock", dir_fd=directory_fd, follow_symlinks=False
            )
        except FileNotFoundError:
            pass
        else:
            if (
                not stat.S_ISSOCK(existing.st_mode)
                or stat.S_IMODE(existing.st_mode) != 0o660
                or (existing.st_uid, existing.st_gid, existing.st_nlink)
                != (0, directory.st_gid, 1)
            ):
                raise UnifiOperationError("unsafe existing executor socket")
            os.unlink("executor.sock", dir_fd=directory_fd)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(SOCKET_PATH)
        os.chown(SOCKET_PATH, 0, directory.st_gid, follow_symlinks=False)
        os.chmod(SOCKET_PATH, 0o660, follow_symlinks=False)
        created = os.stat("executor.sock", dir_fd=directory_fd, follow_symlinks=False)
        socket_identity = (created.st_dev, created.st_ino)
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


def serve_forever():
    handler = _ProtocolHandler()
    with _listener() as listener:
        while True:
            connection, _ = listener.accept()
            with connection:
                handler.handle(connection)


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
    # The recovery decision and cleanup complete before the dependent s6 longrun
    # becomes eligible.  Do not start Java from inside this oneshot.
    outcome = ProductionUnifiExecutor().recover(startup=True)
    if outcome not in _RECOVERY_RESULTS:
        raise UnifiOperationError("unexpected startup recovery result")
    return outcome


def secure_after_linuxserver_init():
    """Restore fixed admin-file ownership changed by LinuxServer's recursive chown."""
    uid, gid = _local_identity()
    root = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    lock = None
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
        try:
            os.stat(LOCK, dir_fd=root, follow_symlinks=False)
        except FileNotFoundError:
            lock = os.open(LOCK, flags | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=root)
            os.fchmod(lock, 0o600)
        else:
            lock = os.open(LOCK, flags, dir_fd=root)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)

        for name in (LOCK, JOURNAL, JOURNAL_NEW):
            try:
                before = os.stat(name, dir_fd=root, follow_symlinks=False)
            except FileNotFoundError:
                continue
            maximum = 0 if name == LOCK else MAX_JOURNAL
            if (
                not stat.S_ISREG(before.st_mode)
                or stat.S_IMODE(before.st_mode) != 0o600
                or (before.st_uid, before.st_gid) not in {(0, 0), (uid, gid)}
                or before.st_dev != os.fstat(root).st_dev
                or not 0 <= before.st_size <= maximum
                or before.st_nlink != 1
            ):
                raise UnifiOperationError("unsafe executor state after initialization")
            descriptor = lock if name == LOCK else os.open(name, flags, dir_fd=root)
            try:
                opened = os.fstat(descriptor)
                if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                    raise UnifiOperationError(
                        "executor state changed after initialization"
                    )
                os.fchown(descriptor, 0, 0)
                os.fchmod(descriptor, 0o600)
                os.fsync(descriptor)
                current = os.stat(name, dir_fd=root, follow_symlinks=False)
                if (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino):
                    raise UnifiOperationError(
                        "executor state changed after initialization"
                    )
            finally:
                if descriptor != lock:
                    os.close(descriptor)
        os.fsync(root)
    except Exception:
        raise UnifiOperationError("executor state normalization failed") from None
    finally:
        if lock is not None:
            os.close(lock)
        os.close(root)
    return "executor_state_secured"


class SocketUnifiExecutionBoundary:
    """Renewer-side adapter for the fixed local executor protocol."""

    def __init__(self):
        self._exclusive = False
        self._installed = None

    def _call(self, operation, arguments):
        request = _request(operation, arguments)
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(SOCKET_TIMEOUT_SECONDS)
        try:
            directory = _validate_socket_directory()
            before = os.stat(SOCKET_PATH, follow_symlinks=False)
            if (
                not stat.S_ISSOCK(before.st_mode)
                or before.st_uid != 0
                or before.st_gid != directory.st_gid
                or stat.S_IMODE(before.st_mode) != 0o660
            ):
                raise ValueError
            connection.connect(SOCKET_PATH)
            after = os.stat(SOCKET_PATH, follow_symlinks=False)
            if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                raise ValueError
            _write_message(connection, request)
            response = _read_message(connection)
            response = _exact_dict(
                response,
                {"version", "ok", "result"}
                if response.get("ok") is True
                else {"version", "ok", "error"},
            )
            if response["version"] != PROTOCOL_VERSION or response["ok"] is not True:
                raise ValueError
            return response["result"]
        except Exception:
            raise UnifiOperationError("UniFi executor request failed") from None
        finally:
            connection.close()

    @contextmanager
    def exclusive(self):
        if self._exclusive:
            raise UnifiOperationError("executor client already active")
        self._exclusive = True
        self._installed = None
        try:
            yield
        finally:
            self._installed = None
            self._exclusive = False

    def inspect_public_state(self):
        if self._exclusive and self._installed is not None:
            return self._installed
        result = _exact_dict(self._call("inspect", {}), {"state"})
        return _decode_state(result["state"])

    def generate_csr(self, policy):
        result = _exact_dict(
            self._call("generate_csr", {"policy": _encode_policy(policy)}), {"csr_pem"}
        )
        return _binary(result["csr_pem"])

    def import_certificate_reply(self, request, *, expected_before):
        if not self._exclusive or self._installed is not None:
            raise UnifiOperationError("exclusive executor client context required")
        if request.before != expected_before:
            raise UnifiOperationError("stale public import request")
        result = _exact_dict(
            self._call("install", {"request": _encode_import_request(request)}),
            {"state"},
        )
        self._installed = _decode_state(result["state"])
        return 0

    def finalize_live_verification(self, expected_leaf_der):
        result = _exact_dict(
            self._call(
                "finalize", {"expected_leaf_der": _encode_binary(expected_leaf_der)}
            ),
            {"outcome"},
        )
        if result["outcome"] != "renewal_finalized":
            raise UnifiOperationError("unexpected executor finalisation result")
        return result["outcome"]

    def recover(self):
        result = _exact_dict(self._call("recover", {}), {"outcome"})
        if result["outcome"] not in _RECOVERY_RESULTS:
            raise UnifiOperationError("unexpected executor recovery result")
        return result["outcome"]


def main(argv=None):
    arguments = sys.argv[1:] if argv is None else argv
    try:
        if arguments == ["serve"]:
            serve_forever()
        elif arguments == ["recover-startup"]:
            outcome = recover_startup()
            print(f"unifi-cert-renewer startup recovery: {outcome}")
        elif arguments == ["secure-after-init"]:
            secure_after_linuxserver_init()
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
