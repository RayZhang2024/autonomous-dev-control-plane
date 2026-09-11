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


@dataclass(frozen=True, slots=True)
class ParseFailure:
    code: ParseFailureCode
    detail: str | None = None

    def __post_init__(self) -> None:
        if type(self.code) is not ParseFailureCode:
            raise TypeError("code must be exactly ParseFailureCode")


class IdentityValidationError(ValueError):
    """Construction failed lexical validation; it makes no external-state claim."""

    def __init__(self, code: IdentityValidationFailureCode) -> None:
        if type(code) is not IdentityValidationFailureCode:
            raise TypeError("code must be exactly IdentityValidationFailureCode")
        self.code = code
        super().__init__(code.value)
