"""Strict, resource-bounded JSON parsing with no policy or authority semantics."""

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
import hashlib
import json
from types import MappingProxyType
from typing import TypeAlias

from .errors import ParseFailure, ParseFailureCode
from .identity import RawSha256

ABSOLUTE_MAX_BYTES = 64 * 1024 * 1024
ABSOLUTE_MAX_DEPTH = 64
ABSOLUTE_MAX_NUMBER_TOKEN_CHARS = 4096
ABSOLUTE_MAX_ABS_EXPONENT = 1_000_000
_MAX_EXPONENT_TEXT = "1000000"


@dataclass(frozen=True, slots=True)
class ParseLimits:
    max_bytes: object
    max_depth: object


FrozenJsonValue: TypeAlias = MappingProxyType | tuple["FrozenJsonValue", ...] | str | Decimal | bool | None


@dataclass(frozen=True, slots=True)
class ParsedJsonDocument:
    raw_bytes: bytes
    raw_sha256: RawSha256
    value: FrozenJsonValue


class _DuplicateMember(Exception):
    pass


class _NumberLimitExceeded(Exception):
    pass


class _InvalidNumber(Exception):
    pass


def _valid_limits(limits: object) -> bool:
    return (
        type(limits) is ParseLimits
        and type(limits.max_bytes) is int
        and type(limits.max_depth) is int
        and 1 <= limits.max_bytes <= ABSOLUTE_MAX_BYTES
        and 1 <= limits.max_depth <= ABSOLUTE_MAX_DEPTH
    )


def _scan_depth(text: str, maximum: int) -> ParseFailure | None:
    expected_closers: list[str] = []
    in_string = False
    escaped = False
    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            expected_closers.append("}")
            if len(expected_closers) > maximum:
                return ParseFailure(ParseFailureCode.DEPTH_LIMIT_EXCEEDED)
        elif char == "[":
            expected_closers.append("]")
            if len(expected_closers) > maximum:
                return ParseFailure(ParseFailureCode.DEPTH_LIMIT_EXCEEDED)
        elif char == "}" or char == "]":
            if not expected_closers or expected_closers[-1] != char:
                return ParseFailure(ParseFailureCode.INVALID_JSON)
            expected_closers.pop()
    return None


def _check_exponent(token: str) -> None:
    marker = token.find("e")
    if marker < 0:
        marker = token.find("E")
    if marker < 0:
        return
    exponent = token[marker + 1 :]
    if exponent[:1] in ("+", "-"):
        exponent = exponent[1:]
    if not exponent or not exponent.isascii() or not exponent.isdecimal():
        raise _InvalidNumber
    significant = exponent.lstrip("0") or "0"
    if len(significant) > len(_MAX_EXPONENT_TEXT) or (
        len(significant) == len(_MAX_EXPONENT_TEXT) and significant > _MAX_EXPONENT_TEXT
    ):
        raise _NumberLimitExceeded


def _parse_number(token: str) -> Decimal:
    if len(token) > ABSOLUTE_MAX_NUMBER_TOKEN_CHARS:
        raise _NumberLimitExceeded
    _check_exponent(token)
    try:
        value = Decimal(token)
    except (InvalidOperation, ValueError) as error:
        raise _InvalidNumber from error
    if not value.is_finite():
        raise _InvalidNumber
    return value


def _reject_constant(_: str) -> object:
    raise _InvalidNumber


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateMember
        result[key] = value
    return result


def _contains_surrogate(value: str) -> bool:
    return any(0xD800 <= ord(character) <= 0xDFFF for character in value)


def _freeze(value: object) -> FrozenJsonValue:
    if type(value) is str:
        if _contains_surrogate(value):
            raise ValueError("surrogate")
        return value
    if type(value) is list:
        return tuple(_freeze(item) for item in value)
    if type(value) is dict:
        frozen: dict[str, FrozenJsonValue] = {}
        for key, item in value.items():
            if _contains_surrogate(key):
                raise ValueError("surrogate")
            frozen[key] = _freeze(item)
        return MappingProxyType(frozen)
    if type(value) in (Decimal, bool) or value is None:
        return value
    raise TypeError("unexpected decoded JSON value")


def parse_trusted_json(raw: object, limits: object) -> ParsedJsonDocument | ParseFailure:
    """Parse exact bytes into a deeply immutable document, never a decision."""
    if type(raw) is not bytes:
        return ParseFailure(ParseFailureCode.INVALID_INPUT_TYPE)
    if not _valid_limits(limits):
        return ParseFailure(ParseFailureCode.INVALID_LIMITS)
    if len(raw) > limits.max_bytes:
        return ParseFailure(ParseFailureCode.BYTE_LIMIT_EXCEEDED)
    if raw.startswith(b"\xef\xbb\xbf"):
        return ParseFailure(ParseFailureCode.UTF8_BOM)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return ParseFailure(ParseFailureCode.INVALID_UTF8)
    depth_failure = _scan_depth(text, limits.max_depth)
    if depth_failure is not None:
        return depth_failure
    try:
        decoded = json.loads(
            text,
            parse_int=_parse_number,
            parse_float=_parse_number,
            parse_constant=_reject_constant,
            object_pairs_hook=_unique_object,
        )
        value = _freeze(decoded)
    except _DuplicateMember:
        return ParseFailure(ParseFailureCode.DUPLICATE_MEMBER)
    except _NumberLimitExceeded:
        return ParseFailure(ParseFailureCode.NUMBER_LIMIT_EXCEEDED)
    except _InvalidNumber:
        return ParseFailure(ParseFailureCode.INVALID_NUMBER)
    except json.JSONDecodeError:
        return ParseFailure(ParseFailureCode.INVALID_JSON)
    except ValueError:
        return ParseFailure(ParseFailureCode.INVALID_UNICODE_SCALAR)
    digest = hashlib.sha256(raw).hexdigest()
    return ParsedJsonDocument(raw, RawSha256(digest), value)
