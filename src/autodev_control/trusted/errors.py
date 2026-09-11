"""Separate structured outcome-code domains for trusted primitives."""

from dataclasses import dataclass
from enum import Enum


class DecisionReasonCode(Enum):
    """Reason codes belonging only to policy/action decisions."""

    UNSPECIFIED = "UNSPECIFIED"


class ParseFailureCode(Enum):
    INVALID_INPUT_TYPE = "INVALID_INPUT_TYPE"
    INVALID_LIMITS = "INVALID_LIMITS"
    BYTE_LIMIT_EXCEEDED = "BYTE_LIMIT_EXCEEDED"
    INVALID_UTF8 = "INVALID_UTF8"
    UTF8_BOM = "UTF8_BOM"
    DEPTH_LIMIT_EXCEEDED = "DEPTH_LIMIT_EXCEEDED"
    INVALID_JSON = "INVALID_JSON"
    DUPLICATE_MEMBER = "DUPLICATE_MEMBER"
    INVALID_UNICODE_SCALAR = "INVALID_UNICODE_SCALAR"
    INVALID_NUMBER = "INVALID_NUMBER"
    NUMBER_LIMIT_EXCEEDED = "NUMBER_LIMIT_EXCEEDED"


class IdentityValidationFailureCode(Enum):
    INVALID_TYPE = "INVALID_TYPE"
    INVALID_LENGTH = "INVALID_LENGTH"
    INVALID_FORMAT = "INVALID_FORMAT"


class ManifestFailureCode(Enum):
    INVALID_INPUT_TYPE = "INVALID_INPUT_TYPE"
    BYTE_LIMIT_EXCEEDED = "BYTE_LIMIT_EXCEEDED"
    PARSE_FAILED = "PARSE_FAILED"
    INVALID_TOP_LEVEL = "INVALID_TOP_LEVEL"
    UNKNOWN_FIELD = "UNKNOWN_FIELD"
    MISSING_FIELD = "MISSING_FIELD"
    INVALID_FIELD_TYPE = "INVALID_FIELD_TYPE"
    INVALID_FIELD_VALUE = "INVALID_FIELD_VALUE"
    DUPLICATE_IDENTITY = "DUPLICATE_IDENTITY"
    UNKNOWN_RESOURCE_REFERENCE = "UNKNOWN_RESOURCE_REFERENCE"
    RESOURCE_KIND_MISMATCH = "RESOURCE_KIND_MISMATCH"
    INVALID_PREDECESSOR = "INVALID_PREDECESSOR"
    EMPTY_REQUIRED_SET = "EMPTY_REQUIRED_SET"


class ResourceFailureCode(Enum):
    INVALID_INPUT_TYPE = "INVALID_INPUT_TYPE"
    INLINE_BYTE_LIMIT_EXCEEDED = "INLINE_BYTE_LIMIT_EXCEEDED"
    DIGEST_MISMATCH = "DIGEST_MISMATCH"
    RESOURCE_KIND_MISMATCH = "RESOURCE_KIND_MISMATCH"
    JSON_BYTE_LIMIT_EXCEEDED = "JSON_BYTE_LIMIT_EXCEEDED"
    PARSE_FAILED = "PARSE_FAILED"


@dataclass(frozen=True, slots=True)
class ParseFailure:
    code: ParseFailureCode
    detail: str | None = None

    def __post_init__(self) -> None:
        if type(self.code) is not ParseFailureCode:
            raise TypeError("code must be exactly ParseFailureCode")


@dataclass(frozen=True, slots=True)
class ManifestFailure:
    code: ManifestFailureCode
    parse_failure: ParseFailure | None = None

    def __post_init__(self) -> None:
        if type(self.code) is not ManifestFailureCode:
            raise TypeError("code must be exactly ManifestFailureCode")
        if self.parse_failure is not None and type(self.parse_failure) is not ParseFailure:
            raise TypeError("parse_failure must be exactly ParseFailure or None")


@dataclass(frozen=True, slots=True)
class ResourceFailure:
    code: ResourceFailureCode
    parse_failure: ParseFailure | None = None

    def __post_init__(self) -> None:
        if type(self.code) is not ResourceFailureCode:
            raise TypeError("code must be exactly ResourceFailureCode")
        if self.parse_failure is not None and type(self.parse_failure) is not ParseFailure:
            raise TypeError("parse_failure must be exactly ParseFailure or None")


class IdentityValidationError(ValueError):
    """Construction failed lexical validation; it makes no external-state claim."""

    def __init__(self, code: IdentityValidationFailureCode) -> None:
        if type(code) is not IdentityValidationFailureCode:
            raise TypeError("code must be exactly IdentityValidationFailureCode")
        self.code = code
        super().__init__(code.value)
