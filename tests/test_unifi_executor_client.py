import json
import os
import stat
import struct
from types import SimpleNamespace

import pytest

import unifi_executor_client as client_protocol
import unifi_executor_service as server_protocol
from unifi_client import UnifiClient, UnifiOperationError


class MemoryConnection:
    def __init__(self, incoming=b""):
        self.incoming = bytearray(incoming)
        self.outgoing = bytearray()

    def settimeout(self, value):
        pass

    def recv(self, length):
        result = bytes(self.incoming[:length])
        del self.incoming[:length]
        return result

    def sendall(self, value):
        self.outgoing.extend(value)


def frame(value):
    data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
    return struct.pack("!I", len(data)) + data


def test_disposable_client_server_transport_supports_public_inspect_and_csr(
    installation_material, monkeypatch
):
    request = installation_material.request

    class PublicExecutor:
        def inspect_public_state(self):
            return request.before

        def generate_csr(self, policy):
            assert policy == request.policy
            return request.csr_pem

    handler = server_protocol._ProtocolHandler(PublicExecutor)

    class LoopbackConnection(MemoryConnection):
        def connect(self, path):
            assert path == client_protocol.SOCKET_PATH

        def sendall(self, value):
            incoming = MemoryConnection(value)
            decoded_request = server_protocol._read_message(incoming)
            result = handler.dispatch(decoded_request)
            self.incoming.extend(frame({"version": 1, "ok": True, "result": result}))

        def close(self):
            pass

    directory_status = SimpleNamespace(
        st_mode=stat.S_IFDIR | 0o750,
        st_uid=0,
        st_gid=os.getgid(),
        st_dev=7,
        st_ino=10,
    )
    socket_status = SimpleNamespace(
        st_mode=stat.S_IFSOCK | 0o660,
        st_uid=0,
        st_gid=os.getgid(),
        st_dev=7,
        st_ino=11,
    )
    monkeypatch.setattr(
        client_protocol,
        "socket",
        SimpleNamespace(
            AF_UNIX=1,
            SOCK_STREAM=1,
            socket=lambda *args: LoopbackConnection(),
        ),
    )
    monkeypatch.setattr(
        client_protocol,
        "os",
        SimpleNamespace(
            stat=lambda path, **kwargs: (
                directory_status
                if path == client_protocol.SOCKET_DIRECTORY
                else socket_status
            )
        ),
    )
    unifi = UnifiClient(client_protocol.SocketUnifiExecutionBoundary())

    assert unifi.inspect_current(request.policy) == request.before
    assert unifi.request_csr(request.policy) == request.csr_pem


def test_client_protocol_and_privileged_targets_are_fixed():
    boundary = client_protocol.SocketUnifiExecutionBoundary()

    assert server_protocol.SocketUnifiExecutionBoundary is type(boundary)
    assert client_protocol.PROTOCOL_VERSION == server_protocol.PROTOCOL_VERSION == 1
    assert client_protocol._OPERATIONS == server_protocol._OPERATIONS
    assert client_protocol.SOCKET_PATH == "/run/unifi-cert-renewer/executor.sock"
    with pytest.raises(TypeError):
        client_protocol.SocketUnifiExecutionBoundary(socket_path="/tmp/other")


def test_client_rejects_unsafe_socket_before_connect(monkeypatch):
    events = []

    class UnusedConnection:
        def settimeout(self, value):
            pass

        def connect(self, path):
            events.append(path)

        def close(self):
            pass

    monkeypatch.setattr(
        client_protocol,
        "socket",
        SimpleNamespace(
            AF_UNIX=1,
            SOCK_STREAM=1,
            socket=lambda *args: UnusedConnection(),
        ),
    )
    monkeypatch.setattr(
        client_protocol,
        "os",
        SimpleNamespace(
            stat=lambda path, **kwargs: SimpleNamespace(
                st_mode=(stat.S_IFDIR | 0o777),
                st_uid=1000,
                st_gid=984,
            )
        ),
    )

    with pytest.raises(UnifiOperationError, match="request failed"):
        client_protocol.SocketUnifiExecutionBoundary().inspect_public_state()

    assert events == []
