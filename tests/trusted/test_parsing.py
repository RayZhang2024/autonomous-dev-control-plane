from decimal import Decimal
from types import MappingProxyType

import pytest

from autodev_control.trusted.errors import ParseFailure, ParseFailureCode
from autodev_control.trusted.parsing import (
    ABSOLUTE_MAX_ABS_EXPONENT, ABSOLUTE_MAX_NUMBER_TOKEN_CHARS, ParseLimits, ParsedJsonDocument, parse_trusted_json,
)


def parse(raw: bytes, limits: ParseLimits | None = None):
    return parse_trusted_json(raw, limits or ParseLimits(10_000, 64))


def failure(raw: object, code: ParseFailureCode, limits: object = ParseLimits(10_000, 64)) -> None:
    result = parse_trusted_json(raw, limits)
    assert isinstance(result, ParseFailure)
    assert result.code is code


def test_limits_are_immutable_carriers_validated_only_by_parser() -> None:
    carrier = ParseLimits(True, 1)
    with pytest.raises(AttributeError): carrier.max_bytes = 3
    for bad in (ParseLimits(0, 1), ParseLimits(-1, 1), ParseLimits(True, 1), ParseLimits(1, False), ParseLimits("1", 1), object()):
        failure(b"null", ParseFailureCode.INVALID_LIMITS, bad)
    assert isinstance(parse(b"0", ParseLimits(1, 1)), ParsedJsonDocument)


@pytest.mark.parametrize("raw, expected", [(b"{}", {}), (b"[]", ()), (b'"hello"', "hello"), (b"123", Decimal("123")), (b"1.25", Decimal("1.25")), (b"1e5", Decimal("1e5")), (b"true", True), (b"false", False), (b"null", None)])
def test_all_top_level_json_forms(raw: bytes, expected: object) -> None:
    document = parse(raw)
    assert isinstance(document, ParsedJsonDocument)
    assert document.value == expected


def test_structured_failure_boundary() -> None:
    failure("null", ParseFailureCode.INVALID_INPUT_TYPE)
    failure(b"\xff", ParseFailureCode.INVALID_UTF8)
    failure(b"\xef\xbb\xbfnull", ParseFailureCode.UTF8_BOM)
    failure(b"/* no */", ParseFailureCode.INVALID_JSON)
    failure(b"null true", ParseFailureCode.INVALID_JSON)
    failure(b" ", ParseFailureCode.INVALID_JSON)
    failure(b'{"a":1,"\\u0061":2}', ParseFailureCode.DUPLICATE_MEMBER)
    failure(b'{"a":"\\ud800"}', ParseFailureCode.INVALID_UNICODE_SCALAR)
    failure(b'{"\\udc00":1}', ParseFailureCode.INVALID_UNICODE_SCALAR)


def test_limits_depth_scanner_and_byte_boundary() -> None:
    assert isinstance(parse(b"{}", ParseLimits(2, 1)), ParsedJsonDocument)
    failure(b"{}", ParseFailureCode.BYTE_LIMIT_EXCEEDED, ParseLimits(1, 1))
    assert isinstance(parse(b'[{}]', ParseLimits(4, 2)), ParsedJsonDocument)
    failure(b'[{}]', ParseFailureCode.DEPTH_LIMIT_EXCEEDED, ParseLimits(4, 1))
    assert isinstance(parse(br'{"x":"\"[]"}', ParseLimits(20, 1)), ParsedJsonDocument)


def test_numbers_are_exact_and_bounded() -> None:
    for token in (b"0", b"-1", b"123456789012345678901234567890", b"0.123456789012345678901234567890", b"1e10000", b"1e-10000"):
        document = parse(token)
        assert isinstance(document.value, Decimal)
        assert document.value == Decimal(token.decode())
    assert isinstance(parse(f"1e{ABSOLUTE_MAX_ABS_EXPONENT}".encode()), ParsedJsonDocument)
    failure(f"1e{ABSOLUTE_MAX_ABS_EXPONENT + 1}".encode(), ParseFailureCode.NUMBER_LIMIT_EXCEEDED)
    assert isinstance(parse(b"1e" + b"0" * 4000 + b"1"), ParsedJsonDocument)
    failure(b"1" * (ABSOLUTE_MAX_NUMBER_TOKEN_CHARS + 1), ParseFailureCode.NUMBER_LIMIT_EXCEEDED)
    for bad in (b"01", b"+1", b".5", b"1.", b"NaN", b"Infinity", b"-Infinity"):
        assert isinstance(parse(bad), ParseFailure)


def test_raw_identity_and_deep_immutability() -> None:
    first, second = parse(b'{"a":1}'), parse(b'{"a": 1}')
    assert first.raw_sha256 != second.raw_sha256
    assert isinstance(first.value, MappingProxyType)
    nested = parse(b'{"a":[{"b":1}]}')
    with pytest.raises(TypeError): nested.value["a"] = ()
    with pytest.raises(TypeError): nested.value["a"][0]["b"] = Decimal(2)
    with pytest.raises(AttributeError): nested.value["a"].append(2)
    with pytest.raises(AttributeError): nested.value = None
