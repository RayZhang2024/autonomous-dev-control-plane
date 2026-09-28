"""Dedicated external fixture-only effect substrate with closed HMAC/JSON frames.

This service is not candidate code and exposes no root-store or fence-release
operation. Its default target fences are FENCED; protected requests fail closed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import errno
import hashlib
import hmac
import json
import secrets
import socket
import socketserver
import threading
import os
import sys
from typing import Mapping

FORMAT = "autodev.g9-substrate-loopback-hmac-json/v1"
MAX_FRAME_BYTES = 64 * 1024
MAX_NONCES = 4096
_ROLE_KEYS = frozenset({"T", "C", "P", "M", "RECOVERY"})
_COMMAND_FIELDS = {
    "F_READ_VERIFY": frozenset({"resource_id", "expected_sha256"}),
    "P_FENCE_READ": frozenset(),
    "M_FENCE_READ": frozenset(),
    "PUBLICATION_PREPARE": frozenset({"effect_id", "payload_sha256"}),
    "MERGE_PREPARE": frozenset({"effect_id", "payload_sha256"}),
    "START_HELD_RECOVER": frozenset({"operation_id", "expected_start_id"}),
}
_ROLE_COMMANDS = {
    "T": frozenset({"F_READ_VERIFY"}),
    "C": frozenset({"F_READ_VERIFY"}),
    "P": frozenset({"F_READ_VERIFY", "P_FENCE_READ", "PUBLICATION_PREPARE"}),
    "M": frozenset({"F_READ_VERIFY", "M_FENCE_READ", "MERGE_PREPARE"}),
    "RECOVERY": frozenset({"START_HELD_RECOVER"}),
}
_TRANSPORT_PHASES = frozenset({"CONNECT", "SEND", "RECEIVE"})
_CONNECT_FAILURE_CLASSES = frozenset({
    "CONNECTION_REFUSED", "ACCESS_DENIED", "TIMED_OUT", "NETWORK_UNREACHABLE",
    "HOST_UNREACHABLE", "OTHER_CONNECT_FAILURE",
})
_WINDOWS_CONNECT_ERROR_CLASSES = {
    10061: "CONNECTION_REFUSED",       # WSAECONNREFUSED
    10013: "ACCESS_DENIED",            # WSAEACCES
    10060: "TIMED_OUT",                # WSAETIMEDOUT
    10051: "NETWORK_UNREACHABLE",      # WSAENETUNREACH
    10065: "HOST_UNREACHABLE",         # WSAEHOSTUNREACH
}
_PORTABLE_CONNECT_ERROR_CLASSES = {
    errno.ECONNREFUSED: "CONNECTION_REFUSED",
    errno.EACCES: "ACCESS_DENIED",
    errno.EPERM: "ACCESS_DENIED",
    errno.ETIMEDOUT: "TIMED_OUT",
    errno.ENETUNREACH: "NETWORK_UNREACHABLE",
    errno.EHOSTUNREACH: "HOST_UNREACHABLE",
}


def _connect_failure_class(exc: OSError) -> str:
    # Python may normalize a socket failure into a concrete OSError subclass.
    if isinstance(exc, ConnectionRefusedError):
        return "CONNECTION_REFUSED"
    if isinstance(exc, PermissionError):
        return "ACCESS_DENIED"
    if isinstance(exc, TimeoutError):
        return "TIMED_OUT"
    winerror = getattr(exc, "winerror", None)
    if type(winerror) is int and winerror in _WINDOWS_CONNECT_ERROR_CLASSES:
        return _WINDOWS_CONNECT_ERROR_CLASSES[winerror]
    socket_errno = getattr(exc, "errno", None)
    if type(socket_errno) is int:
        if socket_errno in _WINDOWS_CONNECT_ERROR_CLASSES:
            return _WINDOWS_CONNECT_ERROR_CLASSES[socket_errno]
        if socket_errno in _PORTABLE_CONNECT_ERROR_CLASSES:
            return _PORTABLE_CONNECT_ERROR_CLASSES[socket_errno]
    return "OTHER_CONNECT_FAILURE"


class SubstrateTransportError(OSError):
    """A socket-operation failure with closed phase/class and raw OS code evidence."""

    __slots__ = ("phase", "failure_class", "os_code")

    def __init__(self, phase: str, failure_class: str | None = None,
                 os_code: int | None = None) -> None:
        if type(phase) is not str or phase not in _TRANSPORT_PHASES:
            raise ValueError("invalid substrate transport phase")
        if phase == "CONNECT":
            if type(failure_class) is not str or failure_class not in _CONNECT_FAILURE_CLASSES:
                raise ValueError("invalid substrate connect failure class")
            if os_code is not None and type(os_code) is not int:
                raise ValueError("invalid substrate connect OS code")
        elif failure_class is not None:
            raise ValueError("failure class is only valid for connect errors")
        elif os_code is not None:
            raise ValueError("OS code is only valid for connect errors")
        self.phase, self.failure_class, self.os_code = phase, failure_class, os_code
        super().__init__()


def _pairs(items: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, member in items:
        if key in value:
            raise ValueError("duplicate JSON member")
        value[key] = member
    return value


def canonical_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def _digest(value: object) -> bool:
    return (type(value) is str and len(value) == 64
            and all(char in "0123456789abcdef" for char in value))


def encode_request(*, role: str, request_id: str, nonce: str, command: str,
                   payload: dict[str, object], key: bytes) -> bytes:
    if (role not in _ROLE_KEYS or type(key) is not bytes or len(key) < 32
            or type(request_id) is not str or not request_id or len(request_id) > 128
            or type(nonce) is not str or not nonce or len(nonce) > 128
            or command not in _COMMAND_FIELDS or type(payload) is not dict
            or set(payload) != set(_COMMAND_FIELDS[command])):
        raise ValueError("request is not in the closed substrate protocol")
    if command not in _ROLE_COMMANDS[role]:
        raise ValueError("role is not authorized for this substrate command")
    if command == "F_READ_VERIFY" and (
            type(payload["resource_id"]) is not str or not payload["resource_id"]
            or not _digest(payload["expected_sha256"])):
        raise ValueError("invalid F read/verify request")
    if command in ("PUBLICATION_PREPARE", "MERGE_PREPARE") and (
            type(payload["effect_id"]) is not str or not payload["effect_id"]
            or not _digest(payload["payload_sha256"])):
        raise ValueError("invalid protected preparation request")
    if command == "START_HELD_RECOVER" and any(
            type(payload[field]) is not str or not payload[field]
            for field in ("operation_id", "expected_start_id")):
        raise ValueError("invalid external recovery request")
    body = {"format": FORMAT, "role": role, "request_id": request_id,
            "nonce": nonce, "command": command, "payload": payload}
    authentication = hmac.new(key, canonical_bytes(body), hashlib.sha256).hexdigest()
    frame = canonical_bytes({**body, "authentication": authentication})
    if len(frame) > MAX_FRAME_BYTES:
        raise ValueError("request exceeds the protocol bound")
    return frame


def _decode_request(frame: bytes, keys: Mapping[str, bytes]) -> dict[str, object]:
    if type(frame) is not bytes or not frame or len(frame) > MAX_FRAME_BYTES:
        raise ValueError("request frame is empty or over the bound")
    try:
        value = json.loads(frame.decode("utf-8"), object_pairs_hook=_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError("non-finite")))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError("malformed request frame") from exc
    fields = {"format", "role", "request_id", "nonce", "command", "payload", "authentication"}
    if type(value) is not dict or set(value) != fields or value["format"] != FORMAT:
        raise ValueError("request fields are not closed")
    role, command = value["role"], value["command"]
    if (role not in _ROLE_KEYS or command not in _COMMAND_FIELDS
            or command not in _ROLE_COMMANDS[role]
            or type(value["request_id"]) is not str or not value["request_id"]
            or type(value["nonce"]) is not str or not value["nonce"]
            or type(value["payload"]) is not dict
            or set(value["payload"]) != set(_COMMAND_FIELDS[command])):
        raise ValueError("role, command, or payload is invalid")
    key = keys.get(role)
    if type(key) is not bytes or len(key) < 32:
        raise ValueError("role is not configured")
    body = {field: value[field] for field in
            ("format", "role", "request_id", "nonce", "command", "payload")}
    expected = hmac.new(key, canonical_bytes(body), hashlib.sha256).hexdigest()
    if (type(value["authentication"]) is not str
            or not hmac.compare_digest(value["authentication"], expected)):
        raise ValueError("request authentication failed")
    # Reuse the encoder's exact value validation after authentication.
    encode_request(role=role, request_id=value["request_id"], nonce=value["nonce"],
                   command=command, payload=value["payload"], key=key)
    return body


@dataclass(slots=True)
class FixtureEffectState:
    candidate_package_id: str
    verified_resources: Mapping[str, bytes]
    p_fence: str = "FENCED"
    m_fence: str = "FENCED"
    recovery_records: dict[tuple[str, str], str] = field(default_factory=dict)
    seen: set[tuple[str, str]] = field(default_factory=set)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def dispatch(self, request: dict[str, object]) -> dict[str, object]:
        role = request["role"]
        command = request["command"]
        payload = request["payload"]
        assert type(payload) is dict
        if command == "F_READ_VERIFY":
            raw = self.verified_resources.get(payload["resource_id"])
            verified = type(raw) is bytes and hashlib.sha256(raw).hexdigest() == payload["expected_sha256"]
            return {"verified": verified, "resource_id": payload["resource_id"],
                    "candidate_package_id": self.candidate_package_id}
        if command == "P_FENCE_READ":
            return {"fence": self.p_fence, "revision": 0,
                    "candidate_package_id": self.candidate_package_id}
        if command == "M_FENCE_READ":
            return {"fence": self.m_fence, "revision": 0,
                    "candidate_package_id": self.candidate_package_id}
        if command in ("PUBLICATION_PREPARE", "MERGE_PREPARE"):
            fence = self.p_fence if role == "P" else self.m_fence
            if fence != "RELEASED":
                return {"accepted": False, "reason": "TARGET_FENCED",
                        "candidate_package_id": self.candidate_package_id}
            return {"accepted": False, "reason": "FIXTURE_EFFECT_EXECUTION_DISABLED",
                    "candidate_package_id": self.candidate_package_id}
        if command == "START_HELD_RECOVER" and role == "RECOVERY":
            identity = (payload["operation_id"], payload["expected_start_id"])
            if identity not in self.recovery_records:
                return {"accepted": False, "reason": "START_HELD_NOT_FOUND",
                        "candidate_package_id": self.candidate_package_id}
            return {"accepted": False, "reason": "RECOVERY_REQUIRES_EXTERNAL_COORDINATOR",
                    "candidate_package_id": self.candidate_package_id}
        raise ValueError("unreachable substrate dispatch")


class _Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        state: FixtureEffectState = self.server.state  # type: ignore[attr-defined]
        keys: Mapping[str, bytes] = self.server.keys  # type: ignore[attr-defined]
        raw = bytearray()
        terminated = False
        trailing = False
        while len(raw) <= MAX_FRAME_BYTES:
            chunk = self.request.recv(min(4096, MAX_FRAME_BYTES + 1 - len(raw)))
            if not chunk:
                break
            end = chunk.find(b"\n")
            if end >= 0:
                raw.extend(chunk[:end])
                terminated = True
                trailing = bool(chunk[end + 1:])
                break
            raw.extend(chunk)
        request_id = ""
        response: dict[str, object]
        try:
            if not terminated or trailing:
                raise ValueError("request must contain exactly one bounded line")
            body = _decode_request(bytes(raw), keys)
            request_id = body["request_id"]
            key = keys[body["role"]]
            replay_key = (body["role"], body["nonce"])
            with state._lock:
                if replay_key in state.seen or len(state.seen) >= MAX_NONCES:
                    raise ValueError("request nonce replay or replay window exhausted")
                state.seen.add(replay_key)
            result = state.dispatch(body)
            response = {"format": FORMAT, "request_id": request_id, "result": result}
            response["authentication"] = hmac.new(key, canonical_bytes(response), hashlib.sha256).hexdigest()
        except Exception:
            # Do not disclose parse, authority, or state details on the wire.
            response = {"format": FORMAT, "request_id": request_id,
                        "result": {"accepted": False, "reason": "REQUEST_REJECTED"}}
            if request_id:
                role = locals().get("body", {}).get("role")
                key = keys.get(role) if isinstance(role, str) else None
                if type(key) is bytes and len(key) >= 32:
                    response["authentication"] = hmac.new(
                        key, canonical_bytes(response), hashlib.sha256
                    ).hexdigest()
        raw_response = canonical_bytes(response) + b"\n"
        if len(raw_response) <= MAX_FRAME_BYTES:
            try:
                self.request.sendall(raw_response)
            except OSError:
                pass


class FixtureSubstrateServer:
    """Loopback-only dedicated process service; no root or fence-release API."""

    def __init__(self, state: FixtureEffectState, keys: Mapping[str, bytes]) -> None:
        if type(state) is not FixtureEffectState:
            raise TypeError("exact fixture substrate state required")
        if set(keys) != set(_ROLE_KEYS) or any(type(key) is not bytes or len(key) < 32
                                               for key in keys.values()):
            raise ValueError("exact per-role HMAC key map is required")
        self._server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _Handler, bind_and_activate=True)
        self._server.daemon_threads = True
        self._server.state = state  # type: ignore[attr-defined]
        self._server.keys = dict(keys)  # type: ignore[attr-defined]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def address(self) -> tuple[str, int]:
        host, port = self._server.server_address
        if host != "127.0.0.1":
            raise RuntimeError("fixture substrate must bind loopback only")
        return host, port

    def start(self) -> None:
        self._thread.start()

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=2)


def call_service(address: tuple[str, int], *, role: str, request_id: str, nonce: str,
                 command: str, payload: dict[str, object], key: bytes) -> dict[str, object]:
    if (type(address) is not tuple or len(address) != 2
            or address[0] != "127.0.0.1" or type(address[1]) is not int
            or not 1 <= address[1] <= 65535):
        raise ValueError("exact IPv4 loopback substrate endpoint required")
    frame = encode_request(role=role, request_id=request_id, nonce=nonce,
                           command=command, payload=payload, key=key)
    client: socket.socket | None = None
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(2)
        client.connect(address)
    except OSError as exc:
        if client is not None:
            client.close()
        winerror = getattr(exc, "winerror", None)
        socket_errno = getattr(exc, "errno", None)
        os_code = (winerror if isinstance(winerror, int)
                   else socket_errno if isinstance(socket_errno, int) else None)
        raise SubstrateTransportError(
            "CONNECT", _connect_failure_class(exc), os_code,
        ) from None
    try:
        try:
            client.sendall(frame + b"\n")
        except OSError:
            raise SubstrateTransportError("SEND") from None
        response = bytearray()
        while len(response) <= MAX_FRAME_BYTES:
            try:
                chunk = client.recv(min(4096, MAX_FRAME_BYTES + 1 - len(response)))
            except OSError:
                raise SubstrateTransportError("RECEIVE") from None
            if not chunk:
                break
            if b"\n" in chunk:
                response.extend(chunk.split(b"\n", 1)[0])
                break
            response.extend(chunk)
    finally:
        client.close()
    try:
        value = json.loads(bytes(response).decode("utf-8"), object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError("substrate response is malformed") from exc
    if (type(value) is not dict or set(value) != {"format", "request_id", "result", "authentication"}
            or value["format"] != FORMAT or value["request_id"] != request_id
            or type(value["result"]) is not dict):
        raise ValueError("substrate response identity is invalid")
    body = {field: value[field] for field in ("format", "request_id", "result")}
    expected = hmac.new(key, canonical_bytes(body), hashlib.sha256).hexdigest()
    if type(value["authentication"]) is not str or not hmac.compare_digest(value["authentication"], expected):
        raise ValueError("substrate response authentication failed")
    return body["result"]


def new_channel_keys() -> dict[str, bytes]:
    """Generate one-use-in-memory secrets; callers must never persist/log them."""
    return {role: secrets.token_bytes(32) for role in sorted(_ROLE_KEYS)}


def _service_bootstrap() -> tuple[FixtureEffectState, dict[str, bytes]]:
    line = sys.stdin.buffer.readline(MAX_FRAME_BYTES + 1)
    if not line or len(line) > MAX_FRAME_BYTES or not line.endswith(b"\n"):
        raise ValueError("invalid bounded service bootstrap")
    value = json.loads(line, object_pairs_hook=_pairs)
    if type(value) is not dict or set(value) != {
            "format", "candidate_package_id", "resources", "channel_keys_hex"}:
        raise ValueError("service bootstrap is not closed")
    if (value["format"] != "autodev.g9-fixture-substrate-bootstrap/v1"
            or not _digest(value["candidate_package_id"])):
        raise ValueError("service bootstrap identity is invalid")
    resources = value["resources"]
    if type(resources) is not list or len(resources) > 4096:
        raise ValueError("resource inventory exceeds the bootstrap bound")
    loaded: dict[str, bytes] = {}
    for item in resources:
        if (type(item) is not dict or set(item) != {"resource_id", "sha256", "path"}
                or type(item["resource_id"]) is not str or not item["resource_id"]
                or not _digest(item["sha256"]) or type(item["path"]) is not str):
            raise ValueError("resource inventory record is malformed")
        with open(item["path"], "rb") as resource_file:
            raw = resource_file.read(MAX_FRAME_BYTES * 16 + 1)
        if len(raw) > MAX_FRAME_BYTES * 16 or hashlib.sha256(raw).hexdigest() != item["sha256"]:
            raise ValueError("resource bytes do not match the frozen inventory")
        if item["resource_id"] in loaded:
            raise ValueError("duplicate resource identity")
        loaded[item["resource_id"]] = raw
    keys_value = value["channel_keys_hex"]
    if type(keys_value) is not dict or set(keys_value) != set(_ROLE_KEYS):
        raise ValueError("exact external channel key set is required")
    keys: dict[str, bytes] = {}
    for role, encoded in keys_value.items():
        if type(encoded) is not str or len(encoded) != 64:
            raise ValueError("channel key is not a 256-bit hex value")
        key = bytes.fromhex(encoded)
        if len(key) != 32:
            raise ValueError("channel key is not a 256-bit value")
        keys[role] = key
    return FixtureEffectState(value["candidate_package_id"], loaded), keys


def _run_service() -> int:
    try:
        state, keys = _service_bootstrap()
        service = FixtureSubstrateServer(state, keys)
        service.start()
        host, port = service.address
        endpoint_identity = hashlib.sha256(canonical_bytes((
            "autodev.g9-fixture-substrate-endpoint/v1", host, port,
            state.candidate_package_id,
        ))).hexdigest()
        sys.stdout.buffer.write(canonical_bytes({
            "format": "autodev.g9-fixture-substrate-ready/v1",
            "pid": os.getpid(), "endpoint": [host, port],
            "candidate_package_id": state.candidate_package_id,
            "endpoint_identity": endpoint_identity,
        }) + b"\n")
        sys.stdout.buffer.flush()
        while True:
            line = sys.stdin.buffer.readline(MAX_FRAME_BYTES + 1)
            if not line or line == b'{"control":"STOP"}\n':
                break
            # Only a single stop control is accepted. Never echo input.
            sys.stdout.buffer.write(b'{"stopped":false}\n')
            sys.stdout.buffer.flush()
        service.close()
        return 0
    except Exception as exc:
        sys.stdout.buffer.write(canonical_bytes({
            "format": "autodev.g9-fixture-substrate-failed/v1",
            "failure_type": type(exc).__name__,
        }) + b"\n")
        sys.stdout.buffer.flush()
        return 2


if __name__ == "__main__" and "--service" in sys.argv[1:]:
    raise SystemExit(_run_service())
