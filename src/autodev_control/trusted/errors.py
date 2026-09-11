"""Separate structured outcome-code domains for trusted primitives."""

from dataclasses import dataclass
from enum import Enum


class DecisionReasonCode(str, Enum):
    """Reason codes belonging only to policy/action decisions."""

    UNSPECIFIED = "UNSPECIFIED"


class ParseFailureCode(str, Enum):
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


class IdentityValidationFailureCode(str, Enum):
    INVALID_TYPE = "INVALID_TYPE"
    INVALID_LENGTH = "INVALID_LENGTH"
    INVALID_FORMAT = "INVALID_FORMAT"


@dataclass(frozen=True, slots=True)
class ParseFailure:
    code: ParseFailureCode
    detail: str | None = None


class IdentityValidationError(ValueError):
    """Construction failed lexical validation; it makes no external-state claim."""

    def __init__(self, code: IdentityValidationFailureCode) -> None:
        self.code = code
        super().__init__(code.value)
