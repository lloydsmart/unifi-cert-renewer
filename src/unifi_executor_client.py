"""Client-only implementation of the fixed UniFi executor socket boundary."""

import base64
import binascii
import json
import os
import socket
import stat
import struct
import time
from contextlib import contextmanager

from unifi_client import (
    MAX_CERTIFICATE_DER_BYTES,
    MAX_KEYTOOL_OUTPUT_CHARS,
    CertificateImportRequest,
    PublicKeystoreState,
    UnifiOperationError,
    build_unifi_csr_command,
    inspect_public_keystore_state,
)

PROTOCOL_VERSION = 1
SOCKET_DIRECTORY = "/run/unifi-cert-renewer"
SOCKET_PATH = f"{SOCKET_DIRECTORY}/executor.sock"
MAX_MESSAGE_BYTES = 8 * 1024 * 1024
SOCKET_TIMEOUT_SECONDS = 300.0
_OPERATIONS = frozenset({"inspect", "generate_csr", "install", "recover", "finalize"})
_RECOVERY_RESULTS = frozenset(
    {
        "no_active_transaction",
        "recovered_old",
        "service_resumed_pending_live_verification",
        "renewal_finalized",
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
    build_unifi_csr_command(policy)
    return {
        "expected_spki_sha256": policy.expected_spki_sha256,
        "subject": policy.subject,
        "dns_sans": list(policy.dns_sans),
        "ip_sans": list(policy.ip_sans),
    }


def _encode_import_request(request):
    if not isinstance(request, CertificateImportRequest):
        raise ValueError
    return {
        "before": _encode_state(request.before),
        "policy": _encode_policy(request.policy),
        "csr_pem": _encode_binary(request.csr_pem),
        "issued_certificate": _encode_binary(request.issued_certificate),
        "trusted_ca_data": _encode_binary(request.trusted_ca_data),
        "lifetime_days": request.lifetime_days,
    }


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


def _read_message(connection):
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


def _write_message(connection, value):
    data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
    if len(data) > MAX_MESSAGE_BYTES:
        raise ValueError
    connection.sendall(struct.pack("!I", len(data)) + data)


def _request(operation, arguments):
    if operation not in _OPERATIONS or not isinstance(arguments, dict):
        raise ValueError
    return {"version": PROTOCOL_VERSION, "operation": operation, "arguments": arguments}


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


def _validate_socket_directory():
    info = os.stat(SOCKET_DIRECTORY, follow_symlinks=False)
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != 0
        or stat.S_IMODE(info.st_mode) != 0o750
    ):
        raise UnifiOperationError("unsafe executor socket directory")
    return info


class SocketUnifiExecutionBoundary:
    """Expose only the five fixed public executor operations to the renewer."""

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
            return _decode_response(_read_message(connection))
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
            self._call("generate_csr", {"policy": _encode_policy(policy)}),
            {"csr_pem"},
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
