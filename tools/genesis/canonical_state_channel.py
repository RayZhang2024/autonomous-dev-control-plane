"""Narrow authenticated T→C channel and immutable C-owned read projections.

The sole InMemoryCanonicalStateBackend is constructed by the C role.  T/P/M
receive typed read-only projections derived from C's closed snapshot; they do
not receive a backend writer object.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import socket
import socketserver
import threading
from typing import Any

FORMAT = "autodev.g9-canonical-state-channel/v1"
MAX_FRAME_BYTES = 16 * 1024


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _pairs(items: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate channel field")
        result[key] = value
    return result


def _projection_digest(projection: dict[str, object]) -> str:
    return hashlib.sha256(b"autodev.g9-canonical-state-projection/v1\0" +
                          _canonical(projection)).hexdigest()


def _backend_projection(backend: object, *, owner_process_id: int,
                        owner_instance_id: str) -> dict[str, object]:
    if type(owner_process_id) is not int or owner_process_id <= 0:
        raise ValueError("C process identity is malformed")
    if type(owner_instance_id) is not str or len(owner_instance_id) != 64:
        raise ValueError("C owner instance identity is malformed")
    state = backend._state
    maps = ("contracts", "authorizations", "tasks", "candidates", "candidate_materializations",
            "operations", "memberships", "attempts", "evidence", "histories", "supersessions")
    counts = {name: len(getattr(state, name)) for name in maps}
    generation = backend.occurrence.backend_generation.value
    preimage = {
        "format": FORMAT, "owner_role": "C", "owner_process_id": owner_process_id,
        "owner_instance_id": owner_instance_id, "backend_generation": generation,
        "state_record_counts": counts,
        "resolved_target_registration_ids": sorted(item.value for item in backend._resolved_targets),
    }
    return {**preimage, "projection_digest": _projection_digest(preimage)}


class _Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        server: CanonicalStateChannelServer = self.server.channel  # type: ignore[attr-defined]
        raw = bytearray()
        while len(raw) <= MAX_FRAME_BYTES:
            data = self.request.recv(min(2048, MAX_FRAME_BYTES + 1 - len(raw)))
            if not data:
                break
            if b"\n" in data:
                raw.extend(data.split(b"\n", 1)[0])
                break
            raw.extend(data)
        try:
            request = json.loads(bytes(raw).decode("utf-8"), object_pairs_hook=_pairs)
            if (type(request) is not dict or set(request) != {
                    "format", "role", "command", "nonce", "authentication"}
                    or request["format"] != FORMAT or request["role"] != "T"
                    or request["command"] != "READ_PROJECTION"
                    or type(request["nonce"]) is not str or len(request["nonce"]) != 32):
                raise ValueError("closed T-to-C request required")
            body = {key: request[key] for key in ("format", "role", "command", "nonce")}
            expected = hmac.new(server.key, _canonical(body), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(request["authentication"], expected):
                raise ValueError("T-to-C authentication failed")
            response_body = {"format": FORMAT, "nonce": request["nonce"],
                             "projection": server.projection}
            response = {**response_body, "authentication": hmac.new(
                server.key, _canonical(response_body), hashlib.sha256).hexdigest()}
        except Exception:
            response = {"format": FORMAT, "rejected": True}
        encoded = _canonical(response) + b"\n"
        if len(encoded) <= MAX_FRAME_BYTES:
            try:
                self.request.sendall(encoded)
            except OSError:
                pass


class CanonicalStateChannelServer:
    """Loopback T-only read-projection endpoint owned by the C process."""

    def __init__(self, backend: object, *, owner_process_id: int,
                 owner_instance_id: str, t_key: bytes) -> None:
        from autodev_control.trusted.backend import InMemoryCanonicalStateBackend

        if type(backend) is not InMemoryCanonicalStateBackend or type(t_key) is not bytes or len(t_key) != 32:
            raise TypeError("exact C backend and T channel key required")
        self.backend, self.key = backend, t_key
        self.projection = _backend_projection(
            backend, owner_process_id=owner_process_id, owner_instance_id=owner_instance_id,
        )
        self.server = socketserver.ThreadingTCPServer(
            ("127.0.0.1", 0), _Handler, bind_and_activate=True,
        )
        self.server.daemon_threads = True
        self.server.channel = self  # type: ignore[attr-defined]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.endpoint = self.server.server_address

    def start(self) -> None:
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


class CanonicalStateReadProjection:
    """Typed read-only candidate projection rebuilt from C's authenticated snapshot."""

    __slots__ = ("client", "projection")

    def __init__(self, projection: dict[str, object]) -> None:
        if not _verify_projection(projection):
            raise ValueError("C canonical-state projection is malformed or stale")
        from autodev_control.trusted.backend import (
            CanonicalStateReadClient, _CanonicalStateStore, _State, _freeze_state,
        )
        store = _CanonicalStateStore(())
        # Empty Stage-B rehearsal state is reconstructed as a read-only typed
        # projection; there is no independent writer or mutable backend object.
        store.state = _freeze_state(_State({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}))
        store.generation = projection["backend_generation"]
        self.client = CanonicalStateReadClient(store)
        self.projection = projection


def _verify_projection(value: object) -> bool:
    fields = {"format", "owner_role", "owner_process_id", "owner_instance_id",
              "backend_generation", "state_record_counts", "resolved_target_registration_ids",
              "projection_digest"}
    if type(value) is not dict or set(value) != fields or value["format"] != FORMAT or value["owner_role"] != "C":
        return False
    preimage = {key: item for key, item in value.items() if key != "projection_digest"}
    counts = value["state_record_counts"]
    return (type(value["owner_process_id"]) is int and value["owner_process_id"] > 0
            and type(value["owner_instance_id"]) is str and len(value["owner_instance_id"]) == 64
            and type(value["backend_generation"]) is int and value["backend_generation"] >= 1
            and type(counts) is dict and set(counts) == {
                "contracts", "authorizations", "tasks", "candidates", "candidate_materializations",
                "operations", "memberships", "attempts", "evidence", "histories", "supersessions"}
            and all(type(count) is int and count == 0 for count in counts.values())
            and value["resolved_target_registration_ids"] == []
            and value["projection_digest"] == _projection_digest(preimage))


class CanonicalStateClient:
    """Authenticated T→C read client; mutation API rejects unprojectable requests."""

    __slots__ = ("address", "key", "projection", "channel_identity")

    def __init__(self, address: tuple[str, int], key: bytes,
                 expected_projection: dict[str, object]) -> None:
        if (type(address) is not tuple or len(address) != 2 or address[0] != "127.0.0.1"
                or type(address[1]) is not int or not 1 <= address[1] <= 65535
                or type(key) is not bytes or len(key) != 32 or not _verify_projection(expected_projection)):
            raise ValueError("T-to-C channel binding is not exact")
        self.address, self.key, self.projection = address, key, expected_projection
        self.channel_identity = hashlib.sha256(_canonical((
            "autodev.g9-T-to-C-state-channel/v1", address[0], address[1],
            expected_projection["owner_instance_id"], expected_projection["projection_digest"],
        ))).hexdigest()
        observed = self.read_projection()
        if observed != expected_projection:
            raise ValueError("C-owned state projection changed during T channel binding")

    def read_projection(self) -> dict[str, object]:
        nonce = secrets.token_hex(16)
        body = {"format": FORMAT, "role": "T", "command": "READ_PROJECTION", "nonce": nonce}
        request = {**body, "authentication": hmac.new(self.key, _canonical(body), hashlib.sha256).hexdigest()}
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            client.settimeout(2)
            client.connect(self.address)
            client.sendall(_canonical(request) + b"\n")
            data = bytearray()
            while len(data) <= MAX_FRAME_BYTES:
                part = client.recv(min(2048, MAX_FRAME_BYTES + 1 - len(data)))
                if not part:
                    break
                if b"\n" in part:
                    data.extend(part.split(b"\n", 1)[0])
                    break
                data.extend(part)
        finally:
            client.close()
        response = json.loads(bytes(data).decode("utf-8"), object_pairs_hook=_pairs)
        if type(response) is not dict or set(response) != {"format", "nonce", "projection", "authentication"}:
            raise ValueError("C state-channel response is not closed")
        response_body = {key: response[key] for key in ("format", "nonce", "projection")}
        expected = hmac.new(self.key, _canonical(response_body), hashlib.sha256).hexdigest()
        if (response["format"] != FORMAT or response["nonce"] != nonce
                or not hmac.compare_digest(response["authentication"], expected)
                or not _verify_projection(response["projection"])):
            raise ValueError("C state-channel response is unauthenticated or malformed")
        return response["projection"]

    def commit_control_state(self, request: object, lease: object, caller_context: object = None) -> object:
        raise PermissionError("Stage-B projection channel does not admit unreviewed control-state mutation")

    def commit_authenticated_request(self, request: object, dependencies: object,
                                    caller_context: object) -> object:
        raise PermissionError("Stage-B projection channel does not admit unreviewed control-state mutation")


_OWNERS: dict[str, CanonicalStateChannelServer] = {}


def register_owner(runtime_run_id: str, server: CanonicalStateChannelServer) -> None:
    if type(runtime_run_id) is not str or runtime_run_id in _OWNERS:
        raise ValueError("C state owner identity is duplicate or malformed")
    _OWNERS[runtime_run_id] = server


def owner_server(runtime_run_id: str) -> CanonicalStateChannelServer | None:
    return _OWNERS.get(runtime_run_id)


def close_owner(runtime_run_id: str) -> None:
    server = _OWNERS.pop(runtime_run_id, None)
    if server is not None:
        server.close()
