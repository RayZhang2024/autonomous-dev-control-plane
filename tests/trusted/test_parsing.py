import hashlib
from decimal import Decimal
from types import MappingProxyType

import pytest

from autodev_control.trusted.errors import DecisionReasonCode, ParseFailure, ParseFailureCode
from autodev_control.trusted.parsing import (
    ABSOLUTE_MAX_ABS_EXPONENT,
    ABSOLUTE_MAX_BYTES,
    ABSOLUTE_MAX_DEPTH,
    ABSOLUTE_MAX_NUMBER_TOKEN_CHARS,
    ParseLimits,
    ParsedJsonDocument,
    parse_trusted_json,
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
    for bad in (
        ParseLimits(0, 1),
        ParseLimits(-1, 1),
        ParseLimits(1, 0),
        ParseLimits(1, -1),
        ParseLimits(ABSOLUTE_MAX_BYTES + 1, 1),
        ParseLimits(1, ABSOLUTE_MAX_DEPTH + 1),
        ParseLimits(True, 1),
        ParseLimits(1, False),
        ParseLimits("1", 1),
        object(),
    ):
        failure(b"null", ParseFailureCode.INVALID_LIMITS, bad)
    assert isinstance(parse(b"0", ParseLimits(1, 1)), ParsedJsonDocument)
    assert isinstance(parse(b"null", ParseLimits(ABSOLUTE_MAX_BYTES, ABSOLUTE_MAX_DEPTH)), ParsedJsonDocument)


@pytest.mark.parametrize("code", ["INVALID_JSON", DecisionReasonCode.UNSPECIFIED])
def test_parse_failure_rejects_plain_and_cross_domain_codes(code: object) -> None:
    with pytest.raises(TypeError):
        ParseFailure(code)


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
    failure(b'{"outer":{"a":1,"a":2}}', ParseFailureCode.DUPLICATE_MEMBER)
    failure(b'{"a":"\\ud800"}', ParseFailureCode.INVALID_UNICODE_SCALAR)
    failure(b'{"\\udc00":1}', ParseFailureCode.INVALID_UNICODE_SCALAR)
    malformed_number = parse(b"1.")
    assert isinstance(malformed_number, ParseFailure)
    assert type(malformed_number.code) is ParseFailureCode
    assert malformed_number.code is ParseFailureCode.INVALID_JSON
    assert malformed_number.detail is None


def test_duplicate_detection_does_not_normalize_unicode_keys() -> None:
    document = parse('{"é":1,"é":2}'.encode())
    assert isinstance(document, ParsedJsonDocument)
    assert document.value["é"] == Decimal(1)
    assert document.value["é"] == Decimal(2)


def test_limits_depth_scanner_and_byte_boundary() -> None:
    assert isinstance(parse(b"{}", ParseLimits(2, 1)), ParsedJsonDocument)
    failure(b"{}", ParseFailureCode.BYTE_LIMIT_EXCEEDED, ParseLimits(1, 1))
    assert isinstance(parse(b'[{}]', ParseLimits(4, 2)), ParsedJsonDocument)
    failure(b'[{}]', ParseFailureCode.DEPTH_LIMIT_EXCEEDED, ParseLimits(4, 1))
    assert isinstance(parse(br'{"x":"\"[]"}', ParseLimits(20, 1)), ParsedJsonDocument)


def test_structural_scan_matches_delimiters() -> None:
    assert isinstance(parse(b'[{"x":1}]'), ParsedJsonDocument)
    failure(b"[}", ParseFailureCode.INVALID_JSON)
    failure(b"{]", ParseFailureCode.INVALID_JSON)
    failure(b"]", ParseFailureCode.INVALID_JSON)


def test_documented_depth_semantics_and_hard_ceiling() -> None:
    assert isinstance(parse(b"0", ParseLimits(1, 1)), ParsedJsonDocument)
    assert isinstance(parse(b"{}", ParseLimits(2, 1)), ParsedJsonDocument)
    assert isinstance(parse(b"[]", ParseLimits(2, 1)), ParsedJsonDocument)
    assert isinstance(parse(b'{"a":[]}', ParseLimits(8, 2)), ParsedJsonDocument)
    assert isinstance(parse(b'[{"a":[1]}]', ParseLimits(11, 3)), ParsedJsonDocument)
    failure(b'{"a":[]}', ParseFailureCode.DEPTH_LIMIT_EXCEEDED, ParseLimits(8, 1))
    malicious = b"[" * (ABSOLUTE_MAX_DEPTH + 1) + b"]" * (ABSOLUTE_MAX_DEPTH + 1)
    failure(malicious, ParseFailureCode.DEPTH_LIMIT_EXCEEDED, ParseLimits(len(malicious), ABSOLUTE_MAX_DEPTH))


def test_numbers_are_exact_and_bounded() -> None:
    for token in (b"0", b"-1", b"123456789012345678901234567890", b"0.123456789012345678901234567890", b"1e10000", b"1e-10000"):
        document = parse(token)
        assert isinstance(document.value, Decimal)
        assert document.value == Decimal(token.decode())
    assert isinstance(parse(f"1e+{ABSOLUTE_MAX_ABS_EXPONENT}".encode()), ParsedJsonDocument)
    failure(f"1e{ABSOLUTE_MAX_ABS_EXPONENT + 1}".encode(), ParseFailureCode.NUMBER_LIMIT_EXCEEDED)
    assert isinstance(parse(f"1e-{ABSOLUTE_MAX_ABS_EXPONENT}".encode()), ParsedJsonDocument)
    failure(f"1e-{ABSOLUTE_MAX_ABS_EXPONENT + 1}".encode(), ParseFailureCode.NUMBER_LIMIT_EXCEEDED)
    assert isinstance(parse(b"1e" + b"0" * 4000 + b"1"), ParsedJsonDocument)
    exact_limit = b"1" + b"0" * (ABSOLUTE_MAX_NUMBER_TOKEN_CHARS - 1)
    assert len(exact_limit) == ABSOLUTE_MAX_NUMBER_TOKEN_CHARS
    exact_document = parse(exact_limit)
    assert isinstance(exact_document, ParsedJsonDocument)
    assert exact_document.value == Decimal(exact_limit.decode())
    failure(b"1" * (ABSOLUTE_MAX_NUMBER_TOKEN_CHARS + 1), ParseFailureCode.NUMBER_LIMIT_EXCEEDED)
    for bad in (b"01", b"+1", b".5", b"1.", b"NaN", b"Infinity", b"-Infinity"):
        assert isinstance(parse(bad), ParseFailure)


def test_unicode_scalar_and_spelling_behavior() -> None:
    pair = parse(br'"\ud83d\ude00"')
    assert isinstance(pair, ParsedJsonDocument)
    assert pair.value == "😀"
    failure(br'"\ud800"', ParseFailureCode.INVALID_UNICODE_SCALAR)
    failure(br'"\udc00"', ParseFailureCode.INVALID_UNICODE_SCALAR)
    failure(br'{"\ud800":1}', ParseFailureCode.INVALID_UNICODE_SCALAR)
    composed = parse('"é"'.encode())
    decomposed = parse('"é"'.encode())
    assert composed.value == "é"
    assert decomposed.value == "é"
    assert composed.value != decomposed.value


def test_raw_identity_and_deep_immutability() -> None:
    exact_raw = b'{"a":1}'
    first, repeated, second = parse(exact_raw), parse(exact_raw), parse(b'{"a": 1}')
    assert first.raw_sha256 == repeated.raw_sha256
    assert first.raw_sha256.value == hashlib.sha256(exact_raw).hexdigest()
    assert first.raw_sha256 != second.raw_sha256
    reordered = parse(b'{"b":2,"a":1}')
    sorted_order = parse(b'{"a":1,"b":2}')
    assert reordered.value == sorted_order.value
    assert reordered.raw_sha256 != sorted_order.raw_sha256
    escaped_unicode = parse(br'{"x":"\u00e9"}')
    literal_unicode = parse('{"x":"é"}'.encode())
    assert escaped_unicode.value == literal_unicode.value
    assert escaped_unicode.raw_sha256 != literal_unicode.raw_sha256
    assert isinstance(first.value, MappingProxyType)
    nested = parse(b'{"a":[{"b":1}]}')
    with pytest.raises(TypeError): nested.value["a"] = ()
    with pytest.raises(TypeError): nested.value["a"][0]["b"] = Decimal(2)
    with pytest.raises(AttributeError): nested.value["a"].append(2)
    with pytest.raises(AttributeError): nested.value = None
    mutable_object_copy = dict(nested.value)
    mutable_object_copy["a"] = ["changed"]
    mutable_array_copy = list(nested.value["a"])
    mutable_array_copy.append("changed")
    assert nested.value["a"] == (MappingProxyType({"b": Decimal(1)}),)
    assert nested.raw_sha256.value == hashlib.sha256(nested.raw_bytes).hexdigest()
