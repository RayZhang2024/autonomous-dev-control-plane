"""Role-side closed client for the G9 loopback substrate.

This module contains no server, fixture state, root-store or fence-release
implementation and is the only substrate transport imported by role adapters.
"""

from __future__ import annotations

import errno
import hashlib
import hmac
import json
import socket
from typing import Mapping

FORMAT = "autodev.g9-substrate-loopback-hmac-json/v1"
MAX_FRAME_BYTES = 64 * 1024
_ROLE_KEYS = frozenset({"T", "C", "P", "M", "RECOVERY"})
_COMMAND_FIELDS = {
    "F_READ_VERIFY": frozenset({"resource_id", "expected_sha256"}),
    "P_FENCE_READ": frozenset(), "M_FENCE_READ": frozenset(),
    "PUBLICATION_PREPARE": frozenset({"effect_id", "payload_sha256"}),
    "MERGE_PREPARE": frozenset({"effect_id", "payload_sha256"}),
    "START_HELD_RECOVER": frozenset({"operation_id", "expected_start_id"}),
}
_ROLE_COMMANDS = {
    "T": frozenset({"F_READ_VERIFY"}), "C": frozenset({"F_READ_VERIFY"}),
    "P": frozenset({"F_READ_VERIFY", "P_FENCE_READ", "PUBLICATION_PREPARE"}),
    "M": frozenset({"F_READ_VERIFY", "M_FENCE_READ", "MERGE_PREPARE"}),
    "RECOVERY": frozenset({"START_HELD_RECOVER"}),
}
_WINDOWS_ERROR_CLASSES = {
    10061: "CONNECTION_REFUSED", 10013: "ACCESS_DENIED", 10060: "TIMED_OUT",
    10051: "NETWORK_UNREACHABLE", 10065: "HOST_UNREACHABLE",
}
_PORTABLE_ERROR_CLASSES = {
    errno.ECONNREFUSED: "CONNECTION_REFUSED", errno.EACCES: "ACCESS_DENIED",
    errno.EPERM: "ACCESS_DENIED", errno.ETIMEDOUT: "TIMED_OUT",
    errno.ENETUNREACH: "NETWORK_UNREACHABLE", errno.EHOSTUNREACH: "HOST_UNREACHABLE",
}
_CONNECT_CLASSES = frozenset({"CONNECTION_REFUSED", "ACCESS_DENIED", "TIMED_OUT",
                              "NETWORK_UNREACHABLE", "HOST_UNREACHABLE", "OTHER_CONNECT_FAILURE"})


class SubstrateTransportError(OSError):
    __slots__ = ("phase", "failure_class", "os_code")

    def __init__(self, phase: str, failure_class: str | None = None,
                 os_code: int | None = None) -> None:
        if phase not in {"CONNECT", "SEND", "RECEIVE"}:
            raise ValueError("invalid substrate transport phase")
        if phase == "CONNECT":
            if failure_class not in _CONNECT_CLASSES or (os_code is not None and type(os_code) is not int):
                raise ValueError("invalid substrate connection failure evidence")
        elif failure_class is not None or os_code is not None:
            raise ValueError("only connection failures carry class/code evidence")
        self.phase, self.failure_class, self.os_code = phase, failure_class, os_code
        super().__init__()


def _connect_failure_class(exc: OSError) -> str:
    if isinstance(exc, ConnectionRefusedError):
        return "CONNECTION_REFUSED"
    if isinstance(exc, PermissionError):
        return "ACCESS_DENIED"
    if isinstance(exc, TimeoutError):
        return "TIMED_OUT"
    winerror = getattr(exc, "winerror", None)
    if type(winerror) is int and winerror in _WINDOWS_ERROR_CLASSES:
        return _WINDOWS_ERROR_CLASSES[winerror]
    code = getattr(exc, "errno", None)
    if type(code) is int:
        return _WINDOWS_ERROR_CLASSES.get(code, _PORTABLE_ERROR_CLASSES.get(code, "OTHER_CONNECT_FAILURE"))
    return "OTHER_CONNECT_FAILURE"


def canonical_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def _pairs(items: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, member in items:
        if key in value:
            raise ValueError("duplicate JSON member")
        value[key] = member
    return value


def _digest(value: object) -> bool:
    return type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def encode_request(*, role: str, request_id: str, nonce: str, command: str,
                   payload: dict[str, object], key: bytes) -> bytes:
    if (role not in _ROLE_KEYS or command not in _COMMAND_FIELDS or command not in _ROLE_COMMANDS[role]
            or type(key) is not bytes or len(key) < 32
            or type(request_id) is not str or not request_id or len(request_id) > 128
            or type(nonce) is not str or not nonce or len(nonce) > 128
            or type(payload) is not dict or set(payload) != set(_COMMAND_FIELDS[command])):
        raise ValueError("request is not in the closed substrate protocol")
    if command == "F_READ_VERIFY" and (
            type(payload["resource_id"]) is not str or not payload["resource_id"]
            or not _digest(payload["expected_sha256"])):
        raise ValueError("invalid F read/verify request")
    if command in ("PUBLICATION_PREPARE", "MERGE_PREPARE") and (
            type(payload["effect_id"]) is not str or not payload["effect_id"]
            or not _digest(payload["payload_sha256"])):
        raise ValueError("invalid protected preparation request")
    if command == "START_HELD_RECOVER" and any(
            type(payload[key]) is not str or not payload[key]
            for key in ("operation_id", "expected_start_id")):
        raise ValueError("invalid external recovery request")
    body = {"format": FORMAT, "role": role, "request_id": request_id,
            "nonce": nonce, "command": command, "payload": payload}
    authentication = hmac.new(key, canonical_bytes(body), hashlib.sha256).hexdigest()
    frame = canonical_bytes({**body, "authentication": authentication})
    if len(frame) > MAX_FRAME_BYTES:
        raise ValueError("request exceeds the protocol bound")
    return frame


def call_service(address: tuple[str, int], *, role: str, request_id: str, nonce: str,
                 command: str, payload: dict[str, object], key: bytes) -> dict[str, object]:
    if (type(address) is not tuple or len(address) != 2 or address[0] != "127.0.0.1"
            or type(address[1]) is not int or not 1 <= address[1] <= 65535):
        raise ValueError("exact IPv4 loopback endpoint required")
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
        winerror, code = getattr(exc, "winerror", None), getattr(exc, "errno", None)
        os_code = winerror if type(winerror) is int else code if type(code) is int else None
        raise SubstrateTransportError("CONNECT", _connect_failure_class(exc), os_code) from None
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
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise ValueError("substrate response is malformed") from None
    if (type(value) is not dict or set(value) != {"format", "request_id", "result", "authentication"}
            or value["format"] != FORMAT or value["request_id"] != request_id
            or type(value["result"]) is not dict):
        raise ValueError("substrate response identity is invalid")
    body = {field: value[field] for field in ("format", "request_id", "result")}
    expected = hmac.new(key, canonical_bytes(body), hashlib.sha256).hexdigest()
    if type(value["authentication"]) is not str or not hmac.compare_digest(value["authentication"], expected):
        raise ValueError("substrate response authentication failed")
    return body["result"]
