"""Closed role-adapter transport; it carries no root-store or release operation."""

from __future__ import annotations

import hashlib
import hmac
import json

FORMAT = "autodev.genesis-ipc/v1"
MAX_FRAME_BYTES = 64 * 1024
_CHANNELS = {
    "authenticated-t-to-c": ("T", "C"),
    "authenticated-t-to-p": ("T", "P"),
    "authenticated-t-to-m": ("T", "M"),
}
_FIELDS = ("format", "channel", "source_role", "destination_role", "request_id", "payload")


def _pairs(items: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


def canonical_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def encode_message(*, channel: str, request_id: str, payload: dict[str, object], key: bytes) -> bytes:
    if channel not in _CHANNELS or type(key) is not bytes or len(key) < 32:
        raise ValueError("invalid channel or authentication key")
    source, destination = _CHANNELS[channel]
    if type(request_id) is not str or not request_id or len(request_id) > 128:
        raise ValueError("invalid request id")
    if type(payload) is not dict or set(payload) != {"command", "nonce"}:
        raise ValueError("payload is not in the closed role protocol")
    if payload["command"] != "BOOTSTRAP_PROBE" or type(payload["nonce"]) is not str or not payload["nonce"]:
        raise ValueError("unsupported role command")
    body = {"format": FORMAT, "channel": channel, "source_role": source,
            "destination_role": destination, "request_id": request_id, "payload": payload}
    signature = hmac.new(key, canonical_bytes(body), hashlib.sha256).hexdigest()
    frame = canonical_bytes({**body, "authentication": signature})
    if len(frame) > MAX_FRAME_BYTES:
        raise ValueError("frame exceeds bound")
    return frame


def decode_message(frame: bytes, *, expected_role: str, key: bytes) -> dict[str, object]:
    if type(frame) is not bytes or len(frame) > MAX_FRAME_BYTES:
        raise ValueError("invalid bounded frame")
    try:
        value = json.loads(frame.decode("utf-8"), object_pairs_hook=_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError("non-finite number")))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError("malformed IPC frame") from exc
    if type(value) is not dict or set(value) != {*_FIELDS, "authentication"}:
        raise ValueError("unknown or missing IPC fields")
    channel = value["channel"]
    if channel not in _CHANNELS:
        raise ValueError("unsupported channel")
    source, destination = _CHANNELS[channel]
    if (value["format"] != FORMAT or value["source_role"] != source
            or value["destination_role"] != destination or destination != expected_role):
        raise ValueError("channel-role mismatch")
    payload = value["payload"]
    if (type(payload) is not dict or set(payload) != {"command", "nonce"}
            or payload["command"] != "BOOTSTRAP_PROBE"
            or type(payload["nonce"]) is not str or not payload["nonce"]):
        raise ValueError("unsupported payload")
    body = {field: value[field] for field in _FIELDS}
    expected = hmac.new(key, canonical_bytes(body), hashlib.sha256).hexdigest()
    if type(value["authentication"]) is not str or not hmac.compare_digest(value["authentication"], expected):
        raise ValueError("IPC authentication failed")
    return body


def encode_ack(*, role: str, request_id: str, nonce: str, key: bytes) -> bytes:
    if role not in ("C", "P", "M") or type(key) is not bytes or len(key) < 32:
        raise ValueError("invalid acknowledgement identity")
    body = {"format": FORMAT, "role": role, "request_id": request_id, "nonce": nonce}
    signature = hmac.new(key, canonical_bytes(body), hashlib.sha256).hexdigest()
    frame = canonical_bytes({**body, "authentication": signature})
    if len(frame) > MAX_FRAME_BYTES:
        raise ValueError("acknowledgement exceeds bound")
    return frame


def decode_ack(frame: bytes, *, expected_role: str, expected_request_id: str,
               expected_nonce: str, key: bytes) -> None:
    if type(frame) is not bytes or len(frame) > MAX_FRAME_BYTES:
        raise ValueError("invalid bounded acknowledgement")
    try:
        value = json.loads(frame.decode("utf-8"), object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError("malformed acknowledgement") from exc
    fields = {"format", "role", "request_id", "nonce", "authentication"}
    if (type(value) is not dict or set(value) != fields or value["format"] != FORMAT
            or value["role"] != expected_role or value["request_id"] != expected_request_id
            or value["nonce"] != expected_nonce):
        raise ValueError("acknowledgement identity mismatch")
    body = {field: value[field] for field in ("format", "role", "request_id", "nonce")}
    expected = hmac.new(key, canonical_bytes(body), hashlib.sha256).hexdigest()
    if type(value["authentication"]) is not str or not hmac.compare_digest(value["authentication"], expected):
        raise ValueError("acknowledgement authentication failed")
